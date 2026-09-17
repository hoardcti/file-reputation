package abusech

import (
	"testing"
	"time"
)

func TestAbuseTime_UnmarshalJSON(t *testing.T) {
	want := time.Date(2026, 9, 17, 14, 18, 1, 0, time.UTC)

	tests := []struct {
		name    string
		input   string
		want    time.Time
		wantErr bool
	}{
		{name: "with zone", input: `"2026-09-17 14:18:01 UTC"`, want: want},
		{name: "without zone", input: `"2026-09-17 14:18:01"`, want: want},
		{name: "empty string", input: `""`, want: time.Time{}},
		{name: "null literal", input: `null`, want: time.Time{}},
		{name: "malformed", input: `"not-a-date"`, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var at AbuseTime
			err := at.UnmarshalJSON([]byte(tc.input))

			if tc.wantErr {
				if nil == err {
					t.Fatalf("UnmarshalJSON(%q): expected error, got nil", tc.input)
				}
				return
			}

			if nil != err {
				t.Fatalf("UnmarshalJSON(%q): unexpected error: %v", tc.input, err)
			}

			if !at.Time().Equal(tc.want) {
				t.Fatalf("UnmarshalJSON(%q): got %v, want %v", tc.input, at.Time(), tc.want)
			}
		})
	}
}
