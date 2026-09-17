package abusech

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hoardcti/file-reputation/internal/network"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// abuseTimeLayout matches the non-RFC3339 timestamps abuse.ch returns,
// e.g. "2026-09-17 14:18:01 UTC".
const abuseTimeLayout = "2006-01-02 15:04:05 MST"

// AbuseTime wraps time.Time to parse abuse.ch's timestamp format.
type AbuseTime time.Time

// UnmarshalJSON implements the json.Unmarshaler interface for AbuseTime.
func (t *AbuseTime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if s == "" || s == "null" {
		*t = AbuseTime(time.Time{})
		return nil
	}
	parsed, err := time.Parse(abuseTimeLayout, s)
	if nil != err {
		return err
	}
	*t = AbuseTime(parsed)
	return nil
}

// Time returns the AbuseTime as a standard time.Time.
func (t AbuseTime) Time() time.Time {
	return time.Time(t)
}

// Dump represents the JSON structure returned by abuse.ch's MalwareBazaar feed.
type Dump map[string][]DumpEntry
type DumpEntry struct {
	SHA256     string     `json:"-"` // populated from the map key
	MD5        string     `json:"md5_hash"`
	SHA1       string     `json:"sha1_hash"`
	Humanhash  string     `json:"humanhash"`
	FirstSeen  AbuseTime  `json:"first_seen"`
	LastSeen   *AbuseTime `json:"last_seen:"` // key really has a trailing colon
	FileName   string     `json:"file_name"`
	FileSize   int64      `json:"file_size"`
	FileType   string     `json:"file_type"`
	FileInfo   *string    `json:"file_info"`
	FileFormat *string    `json:"file_format"`
	FileArch   *string    `json:"file_arch"`
	MIMEType   string     `json:"mime_type"`
	Reporter   string     `json:"reporter"`
	Anonymous  int        `json:"anonymous"`
	Signature  *string    `json:"signature"`
	Imphash    *string    `json:"imphash"`
	TLSH       *string    `json:"tlsh"`
	Telfhash   *string    `json:"telfhash"`
	Gimphash   *string    `json:"gimphash"`
	SSDeep     *string    `json:"ssdeep"`
	Magika     *string    `json:"magika"`
	DhashIcon  *string    `json:"dhash_icon"`
	ArchivePW  *string    `json:"archive_pw"`
	Downloads  int        `json:"downloads"`
	Uploads    int        `json:"uploads"`
	Tags       []Tag      `json:"tags"`
}

// Tag represents a tag associated with a sample in the abuse.ch feed.
type Tag struct {
	Tag      string  `json:"tag"`
	Color    string  `json:"color"`
	Malpedia *string `json:"malpedia"`
}

// Entries returns a slice of DumpEntry, each populated with its corresponding SHA256 hash.
func (d Dump) Entries() []DumpEntry {
	out := make([]DumpEntry, 0, len(d))
	for sha256, entries := range d {
		for _, e := range entries {
			e.SHA256 = sha256
			out = append(out, e)
		}
	}
	return out
}

// get performs an HTTP GET request to the specified URL with the provided authentication key.
func get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if nil != err {
		return nil, err
	}
	return network.Client.Do(req)
}

func Aggregate() error {

	authKey := os.Getenv("ABUSECH_API_KEY")

	// Ensure abuse.ch API key is set in the environment.
	if "" == authKey {
		return fmt.Errorf("ABUSECH_API_KEY environment variable is not set")
	}

	// Fetch the recent samples from abuse.ch's MalwareBazaar feed.
	resp, err := get(context.Background(), "https://mb-api.abuse.ch/v2/files/exports/"+authKey+"/recent.json")
	if nil != err {
		return err
	}

	// Check if the response status code is 200 OK.
	if 200 != resp.StatusCode {
		return fmt.Errorf("abuse.ch API returned status code: %d", resp.StatusCode)
	}

	// Read the response body.
	body, err := io.ReadAll(resp.Body)
	if nil != err {
		return err
	}

	// Close the response body when the function returns to avoid resource leaks.
	defer resp.Body.Close()

	// Unmarshal the JSON response into a Dump struct.
	var dumpResponse Dump
	if err := json.Unmarshal(body, &dumpResponse); nil != err {
		return err
	}

	// Iterate over the entries in the dump response and write each sample to a JSON file.
	for _, sample := range dumpResponse.Entries() {

		filePath := "./out/" + sample.SHA256 + ".json"

		// Check if the file already exists to avoid overwriting existing samples.
		_, err := os.Stat(filePath)
		if os.IsNotExist(err) {
			sampleJSON, err := json.Marshal(sample.ToSample())
			if nil != err {
				return err
			}

			err = os.WriteFile(filePath, sampleJSON, 0644)
			if nil != err {
				return err
			}
		}

	}

	// Return nil to indicate successful aggregation of samples.
	return nil
}
