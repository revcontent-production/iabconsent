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
