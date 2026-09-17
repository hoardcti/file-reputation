package abusech

import (
	"testing"
	"time"
)

func TestSampleInfo_ToSample(t *testing.T) {
	firstSeen := AbuseTime(time.Date(2026, 9, 17, 20, 13, 5, 0, time.UTC))
	lastSeenTime := AbuseTime(time.Date(2026, 9, 17, 22, 0, 0, 0, time.UTC))
	signature := "Remus"

	info := SampleInfo{
		SHA256:    "005b0ef8a642f7d1ceca836d439a514e0d623e3981f6988e52a21bc18d15f13b",
		SHA3_384:  "9f0270186...",
		SHA1:      "a69c212d6d07a7308d7641c177af5134550097ab",
		MD5:       "c7cfdc8f7b80e55ad0fe71b741f9ef7b",
		FirstSeen: firstSeen,
		LastSeen:  &lastSeenTime,
		FileName:  "sample.exe",
		FileSize:  15360,
		Reporter:  "Bitsight",
		Anonymous: 1,
		Signature: &signature,
		Tags:      []string{"exe", "dropped-by-remus"},
		CodeSign: []CodeSign{
			{SubjectCN: strPtr("Example CA")},
		},
		YARARules: []YARARule{
			{RuleName: "WIN_Clipper_Unknown"},
		},
		Comments: []Comment{
			{ID: "42", Comment: "looks bad"},
		},
	}

	sample := info.ToSample()

	if info.SHA256 != sample.Hashes.SHA256 {
		t.Errorf("Hashes.SHA256 = %q, want %q", sample.Hashes.SHA256, info.SHA256)
	}
	if 1 != len(sample.Metadata.Names) || info.FileName != sample.Metadata.Names[0] {
		t.Errorf("Metadata.Names = %v, want [%q]", sample.Metadata.Names, info.FileName)
	}
	if !sample.Submission.Anonymous {
		t.Error("Submission.Anonymous = false, want true (Anonymous == 1)")
	}
	if "Bitsight" != sample.Submission.Reporter {
		t.Errorf("Submission.Reporter = %q, want Bitsight", sample.Submission.Reporter)
	}
	if 1 != len(sample.CodeSign) || nil == sample.CodeSign[0].SubjectCN || "Example CA" != *sample.CodeSign[0].SubjectCN {
		t.Errorf("CodeSign = %+v, want one entry with SubjectCN Example CA", sample.CodeSign)
	}
	if 1 != len(sample.Intelligence.YARAMatches) || "WIN_Clipper_Unknown" != sample.Intelligence.YARAMatches[0].RuleName {
		t.Errorf("Intelligence.YARAMatches = %+v, want one WIN_Clipper_Unknown match", sample.Intelligence.YARAMatches)
	}
	if 1 != len(sample.Intelligence.Comments) || "42" != sample.Intelligence.Comments[0].ID {
		t.Errorf("Intelligence.Comments = %+v, want one comment with id 42", sample.Intelligence.Comments)
	}
	if !sample.FirstSeen.Equal(firstSeen.Time()) {
		t.Errorf("FirstSeen = %v, want %v", sample.FirstSeen, firstSeen.Time())
	}
	if nil == sample.LastSeen || !sample.LastSeen.Equal(lastSeenTime.Time()) {
		t.Errorf("LastSeen = %v, want %v", sample.LastSeen, lastSeenTime.Time())
	}
	if 1 != len(sample.Sources) || SourceName != sample.Sources[0] {
		t.Errorf("Sources = %v, want [%q]", sample.Sources, SourceName)
	}
}

func TestSampleInfo_ToSample_NoLastSeen(t *testing.T) {
	info := SampleInfo{SHA256: "abc"}

	sample := info.ToSample()

	if nil != sample.LastSeen {
		t.Errorf("LastSeen = %v, want nil when SampleInfo.LastSeen is nil", sample.LastSeen)
	}
}

func strPtr(s string) *string { return &s }
