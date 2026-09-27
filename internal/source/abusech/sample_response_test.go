package abusech

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/hoardcti/file-reputation/internal/feed"
)

// TestAbuseTimeUnmarshalJSON checks both abuse.ch timestamp layouts, the "not set" values and
// that a malformed timestamp is rejected with the input quoted.
func TestAbuseTimeUnmarshalJSON(test *testing.T) {
	test.Parallel()

	want := time.Date(2026, 9, 17, 14, 18, 1, 0, time.UTC)
	testCases := []struct {
		name    string
		input   string
		want    time.Time
		wantErr string
	}{
		{name: "export layout with zone", input: `"2026-09-17 14:18:01 UTC"`, want: want},
		{name: "get_info layout without zone", input: `"2026-09-17 14:18:01"`, want: want},
		{name: "empty string", input: `""`},
		{name: "null literal", input: `null`},
		{name: "malformed", input: `"not-a-date"`, wantErr: `parsing abuse.ch timestamp "not-a-date"`},
	}
	for _, testCase := range testCases {
		test.Run(testCase.name, func(subtest *testing.T) {
			subtest.Parallel()

			var timestamp AbuseTime
			err := timestamp.UnmarshalJSON([]byte(testCase.input))

			if "" != testCase.wantErr {
				if nil == err || !strings.Contains(err.Error(), testCase.wantErr) {
					subtest.Errorf("UnmarshalJSON(%s) error = %v, want it to contain %q", testCase.input, err, testCase.wantErr)
				}
				return
			}
			if nil != err {
				subtest.Fatalf("UnmarshalJSON(%s) error = %v, want nil", testCase.input, err)
			}
			if got := time.Time(timestamp); !testCase.want.Equal(got) {
				subtest.Errorf("UnmarshalJSON(%s) = %v, want %v", testCase.input, got, testCase.want)
			}
		})
	}
}

// FuzzAbuseTimeUnmarshalJSON checks that UnmarshalJSON never panics and that every timestamp it
// accepts comes out in UTC, whatever abuse.ch sends.
func FuzzAbuseTimeUnmarshalJSON(fuzzer *testing.F) {
	fuzzer.Add(`"2026-09-17 14:18:01 UTC"`)
	fuzzer.Add(`"2026-09-17 14:18:01"`)
	fuzzer.Add(`"2026-09-17 14:18:01 CEST"`)
	fuzzer.Add(`null`)
	fuzzer.Add(`""`)
	fuzzer.Add(`"not-a-date"`)

	fuzzer.Fuzz(func(test *testing.T, input string) {
		var timestamp AbuseTime
		if err := timestamp.UnmarshalJSON([]byte(input)); nil != err {
			return // Rejecting bad input with an error is allowed; panicking isn't.
		}
		if location := time.Time(timestamp).Location(); time.UTC != location {
			test.Errorf("UnmarshalJSON(%q) location = %v, want UTC", input, location)
		}
	})
}

// TestSampleInfoToSample checks that every upstream field lands in the right place in the
// normalised sample, and that times are converted to UTC.
func TestSampleInfoToSample(test *testing.T) {
	test.Parallel()

	firstSeen := time.Date(2026, 9, 17, 20, 13, 5, 0, time.UTC)
	lastSeen := time.Date(2026, 9, 17, 22, 0, 0, 0, time.FixedZone("CEST", 2*60*60))
	info := SampleInfo{
		SHA256:           KNOWN_HASH,
		SHA3_384:         "9f0270186a2b",
		SHA1:             "a69c212d6d07a7308d7641c177af5134550097ab",
		MD5:              "c7cfdc8f7b80e55ad0fe71b741f9ef7b",
		FirstSeen:        AbuseTime(firstSeen),
		LastSeen:         new(AbuseTime(lastSeen)),
		FileName:         "sample.exe",
		FileSize:         15360,
		FileTypeMIME:     "application/x-dosexec",
		FileType:         "exe",
		FileFormat:       new("PE32"),
		FileArchitecture: new("i386"),
		Reporter:         "Bitsight",
		OriginCountry:    new("NL"),
		Anonymous:        1,
		Signature:        new("Remus"),
		Imphash:          new("imphash"),
		TLSH:             new("tlsh"),
		Telfhash:         new("telfhash"),
		Gimphash:         new("gimphash"),
		SSDeep:           new("ssdeep"),
		Magika:           new("pebin"),
		DhashIcon:        new("dhash"),
		TrID:             json.RawMessage(`"n/a"`),
		Tags:             []string{"exe", "dropped-by-remus"},
		ArchivePassword:  new("infected"),
		CodeSign:         []CodeSign{{SubjectCN: new("Example CA"), CSCBListed: new(true)}},
		DeliveryMethod:   new("email_attachment"),
		FileInformation:  json.RawMessage(`[{"context":"dropped_by"}]`),
		YARARules:        []YARARule{{RuleName: "WIN_Clipper_Unknown", Author: new("analyst")}},
		OLEInformation:   json.RawMessage(`[]`),
		VendorIntel:      map[string]json.RawMessage{"Triage": json.RawMessage(`{"score":"10"}`)},
		Comments:         []Comment{{ID: "42", DateAdded: "2026-09-17 15:00:00", Comment: "looks bad"}},
	}

	want := feed.Sample{
		Hashes: feed.Hashes{
			SHA256:    KNOWN_HASH,
			SHA1:      "a69c212d6d07a7308d7641c177af5134550097ab",
			MD5:       "c7cfdc8f7b80e55ad0fe71b741f9ef7b",
			SHA3_384:  new("9f0270186a2b"),
			TLSH:      new("tlsh"),
			Imphash:   new("imphash"),
			Telfhash:  new("telfhash"),
			Gimphash:  new("gimphash"),
			SSDeep:    new("ssdeep"),
			DhashIcon: new("dhash"),
		},
		Metadata: feed.Metadata{
			Names:           []string{"sample.exe"},
			MIMEType:        "application/x-dosexec",
			Type:            "exe",
			Size:            15360,
			Format:          new("PE32"),
			Architecture:    new("i386"),
			Magika:          new("pebin"),
			TrID:            json.RawMessage(`"n/a"`),
			ArchivePassword: new("infected"),
			FileInformation: json.RawMessage(`[{"context":"dropped_by"}]`),
			OLEInformation:  json.RawMessage(`[]`),
		},
		Intelligence: feed.Intelligence{
			Signature:   new("Remus"),
			Tags:        []string{"exe", "dropped-by-remus"},
			YARAMatches: []feed.YARAMatch{{RuleName: "WIN_Clipper_Unknown", Author: new("analyst")}},
			Comments:    []feed.Comment{{ID: "42", DateAdded: "2026-09-17 15:00:00", Comment: "looks bad"}},
			VendorIntel: map[string]json.RawMessage{"Triage": json.RawMessage(`{"score":"10"}`)},
		},
		Submission: feed.Submission{
			Reporter:       "Bitsight",
			Anonymous:      true,
			OriginCountry:  new("NL"),
			DeliveryMethod: new("email_attachment"),
		},
		CodeSign:  []feed.CodeSign{{SubjectCN: new("Example CA"), CSCBListed: new(true)}},
		Sources:   []string{SOURCE_NAME},
		FirstSeen: firstSeen,
		LastSeen:  new(lastSeen.UTC()),
	}

	if diff := cmp.Diff(want, info.ToSample()); "" != diff {
		test.Errorf("ToSample() mismatch (-want +got):\n%s", diff)
	}
}

// TestSampleInfoToSampleOmitsEmptyValues checks that empty upstream lists and maps become nil, so
// they're left out of the published JSON, and that a missing last sighting stays nil.
func TestSampleInfoToSampleOmitsEmptyValues(test *testing.T) {
	test.Parallel()

	info := SampleInfo{
		SHA256:      SPARSE_HASH,
		CodeSign:    []CodeSign{},
		YARARules:   []YARARule{},
		Comments:    []Comment{},
		VendorIntel: map[string]json.RawMessage{},
	}

	sample := info.ToSample()

	if nil != sample.LastSeen {
		test.Errorf("ToSample().LastSeen = %v, want nil when there's no last sighting", sample.LastSeen)
	}
	if nil != sample.CodeSign {
		test.Errorf("ToSample().CodeSign = %#v, want nil", sample.CodeSign)
	}
	if nil != sample.Intelligence.YARAMatches {
		test.Errorf("ToSample().Intelligence.YARAMatches = %#v, want nil", sample.Intelligence.YARAMatches)
	}
	if nil != sample.Intelligence.Comments {
		test.Errorf("ToSample().Intelligence.Comments = %#v, want nil", sample.Intelligence.Comments)
	}
	if nil != sample.Intelligence.VendorIntel {
		test.Errorf("ToSample().Intelligence.VendorIntel = %#v, want nil", sample.Intelligence.VendorIntel)
	}
	if diff := cmp.Diff([]string{SOURCE_NAME}, sample.Sources); "" != diff {
		test.Errorf("ToSample().Sources mismatch (-want +got):\n%s", diff)
	}
}
