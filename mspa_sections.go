package iabconsent

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

type MspaUsNational struct {
	GppSection
}

type MspaUsCA struct {
	GppSection
}

type MspaUsVA struct {
	GppSection
}

type MspaUsCO struct {
	GppSection
}

type MspaUsUT struct {
	GppSection
}

type MspaUsCT struct {
	GppSection
}

type MspaUsFL struct {
	GppSection
}

type MspaUsMT struct {
	GppSection
}

type MspaUsOR struct {
	GppSection
}

type MspaUsTX struct {
	GppSection
}

type MspaUsDE struct {
	GppSection
}

type MspaUsIA struct {
	GppSection
}

type MspaUsNE struct {
	GppSection
}

type MspaUsNH struct {
	GppSection
}

type MspaUsNJ struct {
	GppSection
}

type MspaUsTN struct {
	GppSection
}

type MspaUsMN struct {
	GppSection
}

// NewMspa returns a supported parser given a GPP Section ID.
// If the SID is not yet supported, it will be null.
func NewMspa(sid int, section string) GppSectionParser {
	switch sid {
	case UsNationalSID:
		return &MspaUsNational{GppSection{sectionId: UsNationalSID, sectionValue: section}}
	case UsCaliforniaSID:
		return &MspaUsCA{GppSection{sectionId: UsCaliforniaSID, sectionValue: section}}
	case UsVirginiaSID:
		return &MspaUsVA{GppSection{sectionId: UsVirginiaSID, sectionValue: section}}
	case UsColoradoSID:
		return &MspaUsCO{GppSection{sectionId: UsColoradoSID, sectionValue: section}}
	case UsUtahSID:
		return &MspaUsUT{GppSection{sectionId: UsUtahSID, sectionValue: section}}
	case UsConnecticutSID:
		return &MspaUsCT{GppSection{sectionId: UsConnecticutSID, sectionValue: section}}
	case UsFloridaSID:
		return &MspaUsFL{GppSection{sectionId: UsFloridaSID, sectionValue: section}}
	case UsMontanaSID:
		return &MspaUsMT{GppSection{sectionId: UsMontanaSID, sectionValue: section}}
	case UsOregonSID:
		return &MspaUsOR{GppSection{sectionId: UsOregonSID, sectionValue: section}}
	case UsTexasSID:
		return &MspaUsTX{GppSection{sectionId: UsTexasSID, sectionValue: section}}
	case UsDelawareSID:
		return &MspaUsDE{GppSection{sectionId: UsDelawareSID, sectionValue: section}}
	case UsIowaSID:
		return &MspaUsIA{GppSection{sectionId: UsIowaSID, sectionValue: section}}
	case UsNebraskaSID:
		return &MspaUsNE{GppSection{sectionId: UsNebraskaSID, sectionValue: section}}
	case UsNewHampshireSID:
		return &MspaUsNH{GppSection{sectionId: UsNewHampshireSID, sectionValue: section}}
	case UsNewJerseySID:
		return &MspaUsNJ{GppSection{sectionId: UsNewJerseySID, sectionValue: section}}
	case UsTennesseeSID:
		return &MspaUsTN{GppSection{sectionId: UsTennesseeSID, sectionValue: section}}
	case UsMinnesotaSID:
		return &MspaUsMN{GppSection{sectionId: UsMinnesotaSID, sectionValue: section}}
	// US-State sections using the newer GPP Section-Header wire format (REV-32).
	case UsMarylandSID:
		return &MspaUsMD{GppSection{sectionId: UsMarylandSID, sectionValue: section}}
	case UsIndianaSID:
		return &MspaUsIN{GppSection{sectionId: UsIndianaSID, sectionValue: section}}
	case UsKentuckySID:
		return &MspaUsKY{GppSection{sectionId: UsKentuckySID, sectionValue: section}}
	case UsRhodeIslandSID:
		return &MspaUsRI{GppSection{sectionId: UsRhodeIslandSID, sectionValue: section}}
	}
	// Skip if no matching struct, as Section ID is not supported yet.
	// Any newly supported Section IDs should be added as cases here.
	return nil
}

type TCFEU struct {
	GppSection
}

type TCFCA struct {
	GppSection
}

type USPV struct {
	GppSection
}

type NotSupported struct {
	GppSection
}

func NewTCFEU(section string) *TCFEU {
	return &TCFEU{GppSection{sectionId: EuropeTCFv2SID, sectionValue: section}}
}

func NewTCFCA(section string) *TCFCA {
	return &TCFCA{GppSection{sectionId: CanadaTCFSID, sectionValue: section}}
}

func NewUSPV(section string) *USPV {
	return &USPV{GppSection{sectionId: UsPVSID, sectionValue: section}}
}

func NewNotSupported(section string, sectionID int) *NotSupported {
	return &NotSupported{GppSection{sectionId: sectionID, sectionValue: section}}
}

func (n *NotSupported) ParseConsent() (GppParsedConsent, error) {
	return nil, errors.New(fmt.Sprintf("Section ID %d is not supported", n.sectionId))
}

func (t *TCFEU) ParseConsent() (GppParsedConsent, error) {
	return ParseV2(t.sectionValue)
}

func (t *TCFCA) ParseConsent() (GppParsedConsent, error) {
	return ParseCAV2(t.sectionValue)
}

func (u *USPV) ParseConsent() (GppParsedConsent, error) {
	return ParseCCPA(u.sectionValue)
}

// parseMspaSection decodes and parses the older "flat" US-National / US-State
// MSPA sections (usnat + MN and the pre-2025 single-mode states). They all share
// the same envelope and differ only in their core field order, so the common
// scaffolding lives here and each section supplies just its field reads via
// readCore:
//
//   - segment 0 is a base64 core whose first 6 bits are MspaVersion (must be 1);
//   - an optional segment 1 is the legacy GPC subsection.
//
// label is the section code (e.g. "usnat", "usca") used in the decode error so
// callers get a section-specific message. The newer combined-MspaMode sections
// (MD/IN/KY/RI) use a different core layout and live in mspa_us_state_v2.go.
func parseMspaSection(sectionValue, label string, readCore func(r *ConsentReader, p *MspaParsedConsent)) (GppParsedConsent, error) {
	var segments = strings.Split(sectionValue, ".")

	var decoded, err = getBytesFromBase64(segments[0])
	if err != nil {
		return nil, errors.Wrap(err, "parse "+label+" consent string")
	}

	var r = NewConsentReader(decoded)

	var p = &MspaParsedConsent{}
	p.Version, _ = r.ReadInt(6)
	if p.Version != 1 {
		return nil, errors.New("non-v1 string passed.")
	}

	// readCore describes the section-specific core payload. The field order in
	// each readCore directly mirrors the IAB section spec linked on the method.
	readCore(r, p)

	if len(segments) > 1 {
		var gppSubsectionConsent *GppSubSection
		gppSubsectionConsent, err = ParseGppSubSections(segments[1:])
		if err != nil {
			return p, err
		}
		p.Gpc = gppSubsectionConsent.Gpc
	}

	return p, r.Err
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-National#core-segment
func (m *MspaUsNational) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usnat", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.SharingOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SensitiveDataProcessingOptOutNotice, _ = r.ReadMspaNotice()
		p.SensitiveDataLimitUseNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.SharingOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(12)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(2)
		p.PersonalDataConsents, _ = r.ReadMspaConsent()
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		// 0 is not a valid value according to the docs for MspaCoveredTransaction. Instead of erroring,
		// return the value of the string, and let downstream processing handle if the value is 0.
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/CA
func (m *MspaUsCA) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usca", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.SharingOptOutNotice, _ = r.ReadMspaNotice()
		p.SensitiveDataLimitUseNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.SharingOptOut, _ = r.ReadMspaOptOut()
		// SensitiveDataProcessingOptOuts, as opposed to Consent.
		p.SensitiveDataProcessingOptOuts, _ = r.ReadMspaBitfieldOptOut(9)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(2)
		p.PersonalDataConsents, _ = r.ReadMspaConsent()
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		// 0 is not a valid value according to the docs for MspaCoveredTransaction. Instead of erroring,
		// return the value of the string, and let downstream processing handle if the value is 0.
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/VA
func (m *MspaUsVA) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usva", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(8)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(1)
		// 0 is not a valid value according to the docs for MspaCoveredTransaction. Instead of erroring,
		// return the value of the string, and let downstream processing handle if the value is 0.
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/CO
func (m *MspaUsCO) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usco", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(7)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(1)
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		// 0 is not a valid value according to the docs for MspaCoveredTransaction. Instead of erroring,
		// return the value of the string, and let downstream processing handle if the value is 0.
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/UT
func (m *MspaUsUT) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usut", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SensitiveDataProcessingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingOptOuts, _ = r.ReadMspaBitfieldOptOut(8)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(1)
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		// 0 is not a valid value according to the docs for MspaCoveredTransaction. Instead of erroring,
		// return the value of the string, and let downstream processing handle if the value is 0.
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/CT
func (m *MspaUsCT) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usct", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(8)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(3)
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		// 0 is not a valid value according to the docs for MspaCoveredTransaction. Instead of erroring,
		// return the value of the string, and let downstream processing handle if the value is 0.
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/FL
func (m *MspaUsFL) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usfl", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(8)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(3)
		p.PersonalDataConsents, _ = r.ReadMspaConsent()
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		// 0 is not a valid value according to the docs for MspaCoveredTransaction. Instead of erroring,
		// return the value of the string, and let downstream processing handle if the value is 0.
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/MT
func (m *MspaUsMT) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usmt", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(8)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(3)
		p.PersonalDataConsents, _ = r.ReadMspaConsent()
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		// 0 is not a valid value according to the docs for MspaCoveredTransaction. Instead of erroring,
		// return the value of the string, and let downstream processing handle if the value is 0.
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/OR
func (m *MspaUsOR) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usor", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(11)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(3)
		p.PersonalDataConsents, _ = r.ReadMspaConsent()
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		// 0 is not a valid value according to the docs for MspaCoveredTransaction. Instead of erroring,
		// return the value of the string, and let downstream processing handle if the value is 0.
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/TX
func (m *MspaUsTX) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "ustx", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(8)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(1)
		p.PersonalDataConsents, _ = r.ReadMspaConsent()
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		// 0 is not a valid value according to the docs for MspaCoveredTransaction. Instead of erroring,
		// return the value of the string, and let downstream processing handle if the value is 0.
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/DE
func (m *MspaUsDE) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usde", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(9)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(5)
		p.PersonalDataConsents, _ = r.ReadMspaConsent()
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		// 0 is not a valid value according to the docs for MspaCoveredTransaction. Instead of erroring,
		// return the value of the string, and let downstream processing handle if the value is 0.
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/IA
func (m *MspaUsIA) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usia", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SensitiveDataProcessingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(8)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(1)
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/NE
func (m *MspaUsNE) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usne", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(8)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(1)
		p.PersonalDataConsents, _ = r.ReadMspaConsent()
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/NH
func (m *MspaUsNH) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usnh", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(8)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(3)
		p.PersonalDataConsents, _ = r.ReadMspaConsent()
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/NJ
func (m *MspaUsNJ) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usnj", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(10)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(5)
		p.PersonalDataConsents, _ = r.ReadMspaConsent()
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/TN
func (m *MspaUsTN) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "ustn", func(r *ConsentReader, p *MspaParsedConsent) {
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(8)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(1)
		p.PersonalDataConsents, _ = r.ReadMspaConsent()
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

// Spec: https://github.com/InteractiveAdvertisingBureau/Global-Privacy-Platform/tree/main/Sections/US-States/MN
func (m *MspaUsMN) ParseConsent() (GppParsedConsent, error) {
	return parseMspaSection(m.sectionValue, "usmn", func(r *ConsentReader, p *MspaParsedConsent) {
		// MN names this field ProcessingNotice; ProcessingNotice and SharingNotice are the same field.
		p.SharingNotice, _ = r.ReadMspaNotice()
		p.SaleOptOutNotice, _ = r.ReadMspaNotice()
		p.TargetedAdvertisingOptOutNotice, _ = r.ReadMspaNotice()
		p.SaleOptOut, _ = r.ReadMspaOptOut()
		p.TargetedAdvertisingOptOut, _ = r.ReadMspaOptOut()
		p.SensitiveDataProcessingConsents, _ = r.ReadMspaBitfieldConsent(8)
		p.KnownChildSensitiveDataConsents, _ = r.ReadMspaBitfieldConsent(1)
		p.PersonalDataConsents, _ = r.ReadMspaConsent()
		p.MspaCoveredTransaction, _ = r.ReadMspaNaYesNo()
		// 0 is not a valid value according to the docs for MspaCoveredTransaction. Instead of erroring,
		// return the value of the string, and let downstream processing handle if the value is 0.
		p.MspaOptOutOptionMode, _ = r.ReadMspaNaYesNo()
		p.MspaServiceProviderMode, _ = r.ReadMspaNaYesNo()
	})
}

func getBytesFromBase64(encoded string) ([]byte, error) {
	buff := []byte(padLastQuantum(encoded))
	decoded := make([]byte, base64.RawURLEncoding.DecodedLen(len(buff)))
	var n, err = base64.RawURLEncoding.Decode(decoded, buff)
	if err != nil {
		return nil, err
	}
	decoded = decoded[:n:n]
	return decoded, nil
}

func padLastQuantum(encoded string) string {
	if (len(encoded) % 4) > 0 {
		return encoded + "A" // pad with zeros
	}

	return encoded
}
