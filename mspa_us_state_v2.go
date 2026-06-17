package iabconsent

import (
	"strings"

	"github.com/pkg/errors"
)

// This file implements the parsers for the newer GPP US-State sections:
// Maryland (24), Indiana (25), Kentucky (26), and Rhode Island (27). See REV-32.
//
// These sections differ from the older flat US-State sections in their core
// field set (notably a single combined MspaMode field, and — for IN/KY/RI — a
// dedicated "Sensitive Data Consents" subsection), but they use the SAME
// segment layout: the section value is split on "." into a core segment
// (segment 0) followed by an optional subsection segment (segment 1). The
// "Section Header" (SectionID / Version / SubSections) described in the IAB
// section specs is part of the client-side API representation and is NOT
// serialized into the encoded consent string payload.
//
// Wire format and field layout verified against the canonical IAB reference
// encoder + test vectors in iabgpp-es PR #106
// (https://github.com/IABTechLab/iabgpp-es/pull/106), e.g. UsMd "BQAA.QA"
// (default), "BVVU.YA" (all fields set, GPC=true); UsIn/UsKy/UsRi "BQAA.AAA"
// (default), "BVVV.kkk" (all fields set, sensitive=[2,1,0,2,1,0,2,1]).
//
// Spec docs:
//
//	MD: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/blob/main/Sections/US-States/MD
//	IN: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/blob/main/Sections/US-States/IN
//	KY: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/blob/main/Sections/US-States/KY
//	RI: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/blob/main/Sections/US-States/RI

type MspaUsMD struct {
	GppSection
}

type MspaUsIN struct {
	GppSection
}

type MspaUsKY struct {
	GppSection
}

type MspaUsRI struct {
	GppSection
}

// MspaMode represents the combined MSPA mode field (Int(2)) introduced by the
// newer GPP US-State sections (MD/IN/KY/RI). It replaces the separate
// MspaOptOutOptionMode / MspaServiceProviderMode fields used by the older flat
// US-State sections.
//
//	0 = Not Applicable
//	1 = Opt-Out Option Mode
//	2 = Service Provider Mode
type MspaMode int

const (
	MspaModeNotApplicable MspaMode = iota
	MspaModeOptOutOption
	MspaModeServiceProvider
	InvalidMspaMode
)

// ReadMspaMode reads a 2-bit combined MSPA mode value.
func (r *ConsentReader) ReadMspaMode() (MspaMode, error) {
	var m, err = r.ReadInt(2)
	return MspaMode(m), err
}

// parseUsStateV2Core parses the core segment shared by MD/IN/KY/RI.
// hasKnownChild controls the IN/KY/RI-only KnownChildSensitiveDataConsents field
// (a single Int(2)); Maryland omits it (and also omits the SensitiveDataProcessing
// subsection entirely).
func parseUsStateV2Core(segment string, name string, hasKnownChild bool) (*MspaParsedConsent, error) {
	var decoded, err = getBytesFromBase64(segment)
	if err != nil {
		return nil, errors.Wrap(err, "parse "+name+" consent string")
	}
	var r = NewConsentReader(decoded)
	var p = &MspaParsedConsent{}

	// Core ordering: MspaVersion, MspaCoveredTransaction, MspaMode first.
	p.Version, _ = r.ReadInt(6) // MspaVersion
	if p.Version != 1 {
		return nil, errors.New("non-v1 string passed.")
	}
	p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
	p.MspaMode, _ = r.ReadMspaMode()
	// ProcessingNotice shares semantics with SharingNotice.
	p.SharingNotice, _ = r.ReadMspaNotice()
	p.SaleOptOutNotice, _ = r.ReadMspaNotice()
	p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
	p.SaleOptOut, _ = r.ReadMspaOptOut()
	p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
	if hasKnownChild {
		// IN/KY/RI carry a single Int(2) KnownChildSensitiveDataConsents value
		// (not a bitfield). Stored at key 0 to fit the shared map field.
		var kc MspaConsent
		kc, _ = r.ReadMspaConsent()
		p.KnownChildSensitiveDataConsents = map[int]MspaConsent{0: kc}
	}
	// AdditionalDataProcessingConsent shares semantics with PersonalDataConsents.
	p.PersonalDataConsents, _ = r.ReadMspaConsent()

	return p, r.Err
}

// parseUsStateV2SensitiveData parses the "Sensitive Data Consents" subsection
// used by IN/KY/RI. Unlike the GPC subsection, it does NOT carry a leading
// SubsectionType field; it is a bare SensitiveDataProcessing N-Bitfield(2,8)
// (8 categories, 2 bits each).
func parseUsStateV2SensitiveData(segment string, p *MspaParsedConsent) error {
	var decoded, err = getBytesFromBase64(segment)
	if err != nil {
		return errors.Wrap(err, "parse sensitive data consent segment")
	}
	var r = NewConsentReader(decoded)
	p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(8)
	return r.Err
}

// parseUsStateV2WithSensitive parses IN/KY/RI, whose only optional subsection is
// the Sensitive Data Consents subsection (segment 1).
func parseUsStateV2WithSensitive(sectionValue, name string) (GppParsedConsent, error) {
	var segments = strings.Split(sectionValue, ".")
	var p, err = parseUsStateV2Core(segments[0], name, true)
	if err != nil {
		return nil, err
	}
	if len(segments) > 1 {
		if err = parseUsStateV2SensitiveData(segments[1], p); err != nil {
			return p, err
		}
	}
	return p, nil
}

func (m *MspaUsMD) ParseConsent() (GppParsedConsent, error) {
	var segments = strings.Split(m.sectionValue, ".")
	// Maryland core omits KnownChildSensitiveDataConsents and SensitiveDataProcessing.
	var p, err = parseUsStateV2Core(segments[0], "usmd", false)
	if err != nil {
		return nil, err
	}
	// Maryland's only optional subsection (segment 1) is the legacy GPC
	// subsection, which carries its own SubsectionType(2) prefix and is parsed
	// by the shared GPC subsection parser.
	if len(segments) > 1 {
		var gppSub *GppSubSection
		gppSub, err = ParseGppSubSections(segments[1:])
		if err != nil {
			return p, err
		}
		p.Gpc = gppSub.Gpc
	}
	return p, nil
}

func (m *MspaUsIN) ParseConsent() (GppParsedConsent, error) {
	return parseUsStateV2WithSensitive(m.sectionValue, "usin")
}

func (m *MspaUsKY) ParseConsent() (GppParsedConsent, error) {
	return parseUsStateV2WithSensitive(m.sectionValue, "usky")
}

func (m *MspaUsRI) ParseConsent() (GppParsedConsent, error) {
	return parseUsStateV2WithSensitive(m.sectionValue, "usri")
}
