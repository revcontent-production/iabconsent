package iabconsent_test

import (
	"encoding/base64"

	"github.com/go-check/check"

	"github.com/revcontent-production/iabconsent"
)

type MspaUsStateV2Suite struct{}

var _ = check.Suite(&MspaUsStateV2Suite{})

// The encoded vectors below are the canonical IAB reference vectors from
// iabgpp-es PR #106 (https://github.com/IABTechLab/iabgpp-es/pull/106), which
// adds the reference UsMd/UsIn/UsKy/UsRi encoders + decoders. They are the
// "canonical encoded strings per state" required by REV-32.

func (s *MspaUsStateV2Suite) TestParseUsMd(c *check.C) {
	// Maryland core: MspaVersion, MspaCoveredTransaction, MspaMode, ProcessingNotice,
	// SaleOptOutNotice, TargetedAdvertisingOptOutNotice, SaleOptOut,
	// TargetedAdvertisingOptOut, AdditionalDataProcessingConsent. No KnownChild,
	// no SensitiveDataProcessing. Optional segment 1 = legacy GPC subsection.
	var dflt = &iabconsent.MspaParsedConsent{
		Version:                1,
		MspaCoveredTransaction: iabconsent.MspaYes,
	}
	var allSet = &iabconsent.MspaParsedConsent{
		Version:                         1,
		MspaCoveredTransaction:          iabconsent.MspaYes,
		MspaMode:                        iabconsent.MspaModeOptOutOption,
		SharingNotice:                   iabconsent.NoticeProvided,
		SaleOptOutNotice:                iabconsent.NoticeProvided,
		TargetedAdvertisingOptOutNotice: iabconsent.NoticeProvided,
		SaleOptOut:                      iabconsent.OptedOut,
		TargetedAdvertisingOptOut:       iabconsent.OptedOut,
		PersonalDataConsents:            iabconsent.NoConsent,
		Gpc:                             true,
	}

	var tcs = []struct {
		desc     string
		section  string
		expected *iabconsent.MspaParsedConsent
	}{
		{"default, gpc segment excluded", "BQAA", dflt},
		{"default, gpc=false", "BQAA.QA", dflt},
		{"all fields set, gpc=true", "BVVU.YA", allSet},
	}
	for _, t := range tcs {
		c.Log("Maryland - " + t.desc)
		var p, err = iabconsent.NewMspa(iabconsent.UsMarylandSID, t.section).ParseConsent()
		c.Assert(err, check.IsNil)
		c.Check(p, check.DeepEquals, t.expected)
	}
}

func (s *MspaUsStateV2Suite) TestParseUsInKyRi(c *check.C) {
	// IN/KY/RI cores are identical (single KnownChildSensitiveDataConsents Int(2)).
	// Optional segment 1 = Sensitive Data Consents (N-Bitfield(2,8), no type prefix).
	var dfltCoreOnly = &iabconsent.MspaParsedConsent{
		Version:                         1,
		MspaCoveredTransaction:          iabconsent.MspaYes,
		KnownChildSensitiveDataConsents: map[int]iabconsent.MspaConsent{0: iabconsent.ConsentNotApplicable},
	}
	// Default with sensitive segment present (all categories Not Applicable).
	var dfltWithSensitive = &iabconsent.MspaParsedConsent{
		Version:                         1,
		MspaCoveredTransaction:          iabconsent.MspaYes,
		KnownChildSensitiveDataConsents: map[int]iabconsent.MspaConsent{0: iabconsent.ConsentNotApplicable},
		SensitiveDataProcessingConsents: map[int]iabconsent.MspaConsent{
			0: iabconsent.ConsentNotApplicable, 1: iabconsent.ConsentNotApplicable,
			2: iabconsent.ConsentNotApplicable, 3: iabconsent.ConsentNotApplicable,
			4: iabconsent.ConsentNotApplicable, 5: iabconsent.ConsentNotApplicable,
			6: iabconsent.ConsentNotApplicable, 7: iabconsent.ConsentNotApplicable,
		},
	}
	var allSet = &iabconsent.MspaParsedConsent{
		Version:                         1,
		MspaCoveredTransaction:          iabconsent.MspaYes,
		MspaMode:                        iabconsent.MspaModeOptOutOption,
		SharingNotice:                   iabconsent.NoticeProvided,
		SaleOptOutNotice:                iabconsent.NoticeProvided,
		TargetedAdvertisingOptOutNotice: iabconsent.NoticeProvided,
		SaleOptOut:                      iabconsent.OptedOut,
		TargetedAdvertisingOptOut:       iabconsent.OptedOut,
		KnownChildSensitiveDataConsents: map[int]iabconsent.MspaConsent{0: iabconsent.NoConsent},
		PersonalDataConsents:            iabconsent.NoConsent,
		SensitiveDataProcessingConsents: map[int]iabconsent.MspaConsent{
			0: iabconsent.Consent, 1: iabconsent.NoConsent, 2: iabconsent.ConsentNotApplicable,
			3: iabconsent.Consent, 4: iabconsent.NoConsent, 5: iabconsent.ConsentNotApplicable,
			6: iabconsent.Consent, 7: iabconsent.NoConsent,
		},
	}

	var states = []struct {
		desc string
		sid  int
	}{
		{"Indiana", iabconsent.UsIndianaSID},
		{"Kentucky", iabconsent.UsKentuckySID},
		{"Rhode Island", iabconsent.UsRhodeIslandSID},
	}
	var tcs = []struct {
		desc     string
		section  string
		expected *iabconsent.MspaParsedConsent
	}{
		{"default, sensitive segment excluded", "BQAA", dfltCoreOnly},
		{"default with sensitive segment", "BQAA.AAA", dfltWithSensitive},
		{"all fields set", "BVVV.kkk", allSet},
	}
	for _, st := range states {
		for _, t := range tcs {
			c.Log(st.desc + " - " + t.desc)
			var p, err = iabconsent.NewMspa(st.sid, t.section).ParseConsent()
			c.Assert(err, check.IsNil)
			c.Check(p, check.DeepEquals, t.expected)
		}
	}
}

// TestParseUsMdViaGppString exercises the full GPP string path
// (ParseGppConsent -> MapGppSectionToParser -> NewMspa) to confirm SID dispatch
// for the new sections, using a hand-built GPP header for section 24.
func (s *MspaUsStateV2Suite) TestParseUsMdViaGppString(c *check.C) {
	var hdr bitWriter
	hdr.writeInt(3, 6) // Type = GPP header
	hdr.writeInt(1, 6) // Version
	hdr.writeFibRange([]int{iabconsent.UsMarylandSID})
	var gpp = hdr.encode() + "~BVVU.YA"

	var consents, err = iabconsent.ParseGppConsent(gpp)
	c.Assert(err, check.IsNil)
	var md, ok = consents[iabconsent.UsMarylandSID]
	c.Assert(ok, check.Equals, true)
	c.Check(md, check.DeepEquals, &iabconsent.MspaParsedConsent{
		Version:                         1,
		MspaCoveredTransaction:          iabconsent.MspaYes,
		MspaMode:                        iabconsent.MspaModeOptOutOption,
		SharingNotice:                   iabconsent.NoticeProvided,
		SaleOptOutNotice:                iabconsent.NoticeProvided,
		TargetedAdvertisingOptOutNotice: iabconsent.NoticeProvided,
		SaleOptOut:                      iabconsent.OptedOut,
		TargetedAdvertisingOptOut:       iabconsent.OptedOut,
		PersonalDataConsents:            iabconsent.NoConsent,
		Gpc:                             true,
	})
}

func (s *MspaUsStateV2Suite) TestParseUsStateV2Errors(c *check.C) {
	var tcs = []struct {
		desc    string
		sid     int
		section string
		errLike string
	}{
		{"md bad base64 core", iabconsent.UsMarylandSID, "$%&*(", "parse usmd consent string.*illegal base64.*"},
		{"in bad base64 core", iabconsent.UsIndianaSID, "$%&*(", "parse usin consent string.*illegal base64.*"},
	}
	for _, t := range tcs {
		c.Log(t.desc)
		var p, err = iabconsent.NewMspa(t.sid, t.section).ParseConsent()
		c.Check(p, check.IsNil)
		c.Check(err, check.ErrorMatches, t.errLike)
	}
}

// bitWriter is a minimal MSB-first bit writer used only to construct a GPP
// top-level header for the end-to-end routing test above. Section-level decode
// tests use the canonical iabgpp-es vectors directly.
type bitWriter struct {
	bits []byte
}

func (w *bitWriter) writeInt(val int, n int) {
	for i := n - 1; i >= 0; i-- {
		w.bits = append(w.bits, byte((val>>uint(i))&1))
	}
}

func (w *bitWriter) writeBool(b bool) {
	if b {
		w.bits = append(w.bits, 1)
	} else {
		w.bits = append(w.bits, 0)
	}
}

// writeFibInt writes n (n >= 1) using canonical Fibonacci coding, matching
// ConsentReader.ReadFibonacciInt.
func (w *bitWriter) writeFibInt(n int) {
	fibs := []int{1, 2, 3, 5, 8, 13, 21, 34, 55, 89}
	k := 0
	for k < len(fibs) && fibs[k] <= n {
		k++
	}
	k--
	bits := make([]byte, k+1)
	rem := n
	for i := k; i >= 0; i-- {
		if fibs[i] <= rem {
			bits[i] = 1
			rem -= fibs[i]
		}
	}
	w.bits = append(w.bits, bits...)
	w.bits = append(w.bits, 1) // terminating 1
}

// writeFibRange writes a Range(Fibonacci) of single IDs (sorted ascending),
// matching ConsentReader.ReadFibonacciRange.
func (w *bitWriter) writeFibRange(ids []int) {
	w.writeInt(len(ids), 12)
	last := 0
	for _, id := range ids {
		w.writeBool(false)
		w.writeFibInt(id - last)
		last = id
	}
}

func (w *bitWriter) encode() string {
	nbytes := (len(w.bits) + 7) / 8
	buf := make([]byte, nbytes)
	for i, b := range w.bits {
		if b == 1 {
			buf[i/8] |= 1 << uint(7-(i%8))
		}
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

// encodeUsStateV2Core encodes the MD/IN/KY/RI core segment (segment 0) from a
// parsed consent, writing each field in the exact order parseUsStateV2Core
// reads it. hasKnownChild includes the IN/KY/RI KnownChildSensitiveDataConsents
// Int(2); Maryland omits it. The encoder is the inverse of the parser and is
// pinned to the canonical iabgpp-es reference vectors by
// TestUsStateV2EncoderMatchesCanonicalVectors below, so the mixed-value vectors
// it mints for the fixture table are guaranteed to be canonical encodings.
func encodeUsStateV2Core(p *iabconsent.MspaParsedConsent, hasKnownChild bool) string {
	var w bitWriter
	w.writeInt(p.Version, 6) // MspaVersion
	w.writeInt(int(p.MspaCoveredTransaction), 2)
	w.writeInt(int(p.MspaMode), 2)
	w.writeInt(int(p.SharingNotice), 2) // ProcessingNotice == SharingNotice
	w.writeInt(int(p.SaleOptOutNotice), 2)
	w.writeInt(int(p.TargetedAdvertisingOptOutNotice), 2)
	w.writeInt(int(p.SaleOptOut), 2)
	w.writeInt(int(p.TargetedAdvertisingOptOut), 2)
	if hasKnownChild {
		w.writeInt(int(p.KnownChildSensitiveDataConsents[0]), 2)
	}
	w.writeInt(int(p.PersonalDataConsents), 2) // AdditionalDataProcessingConsent
	return w.encode()
}

// encodeUsStateV2Sensitive encodes the IN/KY/RI "Sensitive Data Consents"
// subsection (segment 1): a bare SensitiveDataProcessing N-Bitfield(2,8) with no
// SubsectionType prefix, mirroring parseUsStateV2SensitiveData.
func encodeUsStateV2Sensitive(sensitive map[int]iabconsent.MspaConsent) string {
	var w bitWriter
	for i := 0; i < 8; i++ {
		w.writeInt(int(sensitive[i]), 2)
	}
	return w.encode()
}

// TestUsStateV2EncoderMatchesCanonicalVectors pins encodeUsStateV2Core /
// encodeUsStateV2Sensitive to the canonical iabgpp-es PR #106 reference vectors.
// If these pass, the encoder reproduces the IAB reference encoder bit-for-bit,
// so any additional vector it mints (used by TestParseUsStateV2Fixtures) is a
// real canonical encoding rather than a self-consistent invention.
func (s *MspaUsStateV2Suite) TestUsStateV2EncoderMatchesCanonicalVectors(c *check.C) {
	// Maryland core (no KnownChild): default "BQAA", all-fields-set "BVVU".
	c.Check(encodeUsStateV2Core(&iabconsent.MspaParsedConsent{
		Version:                1,
		MspaCoveredTransaction: iabconsent.MspaYes,
	}, false), check.Equals, "BQAA")
	c.Check(encodeUsStateV2Core(&iabconsent.MspaParsedConsent{
		Version:                         1,
		MspaCoveredTransaction:          iabconsent.MspaYes,
		MspaMode:                        iabconsent.MspaModeOptOutOption,
		SharingNotice:                   iabconsent.NoticeProvided,
		SaleOptOutNotice:                iabconsent.NoticeProvided,
		TargetedAdvertisingOptOutNotice: iabconsent.NoticeProvided,
		SaleOptOut:                      iabconsent.OptedOut,
		TargetedAdvertisingOptOut:       iabconsent.OptedOut,
		PersonalDataConsents:            iabconsent.NoConsent,
	}, false), check.Equals, "BVVU")

	// IN/KY/RI core (with KnownChild): default "BQAA", all-fields-set "BVVV".
	c.Check(encodeUsStateV2Core(&iabconsent.MspaParsedConsent{
		Version:                         1,
		MspaCoveredTransaction:          iabconsent.MspaYes,
		KnownChildSensitiveDataConsents: map[int]iabconsent.MspaConsent{0: iabconsent.ConsentNotApplicable},
	}, true), check.Equals, "BQAA")
	c.Check(encodeUsStateV2Core(&iabconsent.MspaParsedConsent{
		Version:                         1,
		MspaCoveredTransaction:          iabconsent.MspaYes,
		MspaMode:                        iabconsent.MspaModeOptOutOption,
		SharingNotice:                   iabconsent.NoticeProvided,
		SaleOptOutNotice:                iabconsent.NoticeProvided,
		TargetedAdvertisingOptOutNotice: iabconsent.NoticeProvided,
		SaleOptOut:                      iabconsent.OptedOut,
		TargetedAdvertisingOptOut:       iabconsent.OptedOut,
		KnownChildSensitiveDataConsents: map[int]iabconsent.MspaConsent{0: iabconsent.NoConsent},
		PersonalDataConsents:            iabconsent.NoConsent,
	}, true), check.Equals, "BVVV")

	// Sensitive Data Consents subsection: all Not-Applicable "AAA", canonical
	// mixed set "kkk" (= [2,1,0,2,1,0,2,1]).
	c.Check(encodeUsStateV2Sensitive(map[int]iabconsent.MspaConsent{
		0: iabconsent.ConsentNotApplicable, 1: iabconsent.ConsentNotApplicable,
		2: iabconsent.ConsentNotApplicable, 3: iabconsent.ConsentNotApplicable,
		4: iabconsent.ConsentNotApplicable, 5: iabconsent.ConsentNotApplicable,
		6: iabconsent.ConsentNotApplicable, 7: iabconsent.ConsentNotApplicable,
	}), check.Equals, "AAA")
	c.Check(encodeUsStateV2Sensitive(map[int]iabconsent.MspaConsent{
		0: iabconsent.Consent, 1: iabconsent.NoConsent, 2: iabconsent.ConsentNotApplicable,
		3: iabconsent.Consent, 4: iabconsent.NoConsent, 5: iabconsent.ConsentNotApplicable,
		6: iabconsent.Consent, 7: iabconsent.NoConsent,
	}), check.Equals, "kkk")
}

// TestParseUsStateV2Fixtures is the fixture-style table (modelled on
// mspa_parsed_consent_fixture_test.go + TestParseMSPA) for the newer combined-
// MspaMode states. Each case carries an expected *MspaParsedConsent plus the
// optional GPC / Sensitive-Data subsection; the canonical encoded section string
// is minted by the pinned encoder above, then routed back through
// NewMspa(sid, section).ParseConsent() and asserted with DeepEquals. This gives
// the new states the same representative mixed-value coverage (notices, opt-
// outs, MspaMode, known-child, per-category sensitive data, GPC true/false) the
// older flat states already have.
func (s *MspaUsStateV2Suite) TestParseUsStateV2Fixtures(c *check.C) {
	// mixedSensitive is a representative per-category Sensitive Data set used by
	// the IN/KY/RI cases.
	var mixedSensitive = map[int]iabconsent.MspaConsent{
		0: iabconsent.Consent, 1: iabconsent.NoConsent, 2: iabconsent.ConsentNotApplicable,
		3: iabconsent.Consent, 4: iabconsent.NoConsent, 5: iabconsent.ConsentNotApplicable,
		6: iabconsent.Consent, 7: iabconsent.NoConsent,
	}

	var tcs []struct {
		desc     string
		sid      int
		section  string
		expected *iabconsent.MspaParsedConsent
	}

	// --- Maryland (no KnownChild, no Sensitive subsection; optional GPC). ---
	var mdMixedCore = &iabconsent.MspaParsedConsent{
		Version:                         1,
		MspaCoveredTransaction:          iabconsent.MspaYes,
		MspaMode:                        iabconsent.MspaModeServiceProvider,
		SharingNotice:                   iabconsent.NoticeProvided,
		SaleOptOutNotice:                iabconsent.NoticeNotProvided,
		TargetedAdvertisingOptOutNotice: iabconsent.NoticeNotApplicable,
		SaleOptOut:                      iabconsent.OptedOut,
		TargetedAdvertisingOptOut:       iabconsent.NotOptedOut,
		PersonalDataConsents:            iabconsent.Consent,
	}
	var mdCore = encodeUsStateV2Core(mdMixedCore, false)
	tcs = append(tcs,
		struct {
			desc     string
			sid      int
			section  string
			expected *iabconsent.MspaParsedConsent
		}{"Maryland mixed, no subsection (gpc=false)", iabconsent.UsMarylandSID, mdCore, mdMixedCore},
	)
	// Same core with a GPC=true subsection (canonical ".YA").
	var mdMixedGpc = clonePc(mdMixedCore)
	mdMixedGpc.Gpc = true
	tcs = append(tcs,
		struct {
			desc     string
			sid      int
			section  string
			expected *iabconsent.MspaParsedConsent
		}{"Maryland mixed, gpc=true", iabconsent.UsMarylandSID, mdCore + ".YA", mdMixedGpc},
	)

	// --- IN / KY / RI (KnownChild Int(2) + optional Sensitive subsection). ---
	for _, st := range []struct {
		desc string
		sid  int
	}{
		{"Indiana", iabconsent.UsIndianaSID},
		{"Kentucky", iabconsent.UsKentuckySID},
		{"Rhode Island", iabconsent.UsRhodeIslandSID},
	} {
		// Core-only (no Sensitive subsection): SensitiveDataProcessingConsents stays nil.
		var coreOnly = &iabconsent.MspaParsedConsent{
			Version:                         1,
			MspaCoveredTransaction:          iabconsent.MspaYes,
			MspaMode:                        iabconsent.MspaModeServiceProvider,
			SharingNotice:                   iabconsent.NoticeProvided,
			SaleOptOutNotice:                iabconsent.NoticeNotProvided,
			TargetedAdvertisingOptOutNotice: iabconsent.NoticeProvided,
			SaleOptOut:                      iabconsent.OptedOut,
			TargetedAdvertisingOptOut:       iabconsent.NotOptedOut,
			KnownChildSensitiveDataConsents: map[int]iabconsent.MspaConsent{0: iabconsent.NoConsent},
			PersonalDataConsents:            iabconsent.Consent,
		}
		var core = encodeUsStateV2Core(coreOnly, true)
		tcs = append(tcs,
			struct {
				desc     string
				sid      int
				section  string
				expected *iabconsent.MspaParsedConsent
			}{st.desc + " mixed, core only", st.sid, core, coreOnly},
		)
		// Same core + a mixed Sensitive Data subsection.
		var withSensitive = clonePc(coreOnly)
		withSensitive.SensitiveDataProcessingConsents = mixedSensitive
		tcs = append(tcs,
			struct {
				desc     string
				sid      int
				section  string
				expected *iabconsent.MspaParsedConsent
			}{st.desc + " mixed, with sensitive subsection", st.sid, core + "." + encodeUsStateV2Sensitive(mixedSensitive), withSensitive},
		)
	}

	for _, t := range tcs {
		c.Log(t.desc + " - " + t.section)
		var p, err = iabconsent.NewMspa(t.sid, t.section).ParseConsent()
		c.Assert(err, check.IsNil)
		c.Check(p, check.DeepEquals, t.expected)
	}
}

// clonePc returns a shallow copy of a MspaParsedConsent for building related
// fixture expectations (the maps are treated as read-only in these tests).
func clonePc(p *iabconsent.MspaParsedConsent) *iabconsent.MspaParsedConsent {
	var cp = *p
	return &cp
}
