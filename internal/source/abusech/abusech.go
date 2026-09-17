package abusech

import (
	"context"
	"encoding/json"
	"fmt"
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

func (t AbuseTime) Time() time.Time {
	return time.Time(t)
}

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

type Tag struct {
	Tag      string  `json:"tag"`
	Color    string  `json:"color"`
	Malpedia *string `json:"malpedia"`
}

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

var client = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100, // default is 2, which throttles same-host polling
		IdleConnTimeout:     90 * time.Second,
		ForceAttemptHTTP2:   true,
	},
}

func get(ctx context.Context, url string, authKey string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if nil != err {
		return nil, err
	}
	req.Header.Set("Auth-Key", authKey)
	return client.Do(req)
}

func Aggregate() error {

	authKey := os.Getenv("ABUSECH_API_KEY")

	resp, err := get(context.Background(), "https://mb-api.abuse.ch/v2/files/exports/"+authKey+"/recent.json", authKey)
	if nil != err {
		return err
	}

	body, err := io.ReadAll(resp.Body)
	if nil != err {
		return err
	}

	defer resp.Body.Close()

	var dumpResponse Dump
	if err := json.Unmarshal(body, &dumpResponse); nil != err {
		return err
	}

	if 200 != resp.StatusCode {
		return fmt.Errorf("abuse.ch API returned status code: %d", resp.StatusCode)
	}

	for _, sample := range dumpResponse.Entries() {

		filePath := "./out/" + sample.SHA256 + ".json"

		_, err := os.Stat(filePath)
		if os.IsNotExist(err) {
			sampleJSON, err := json.MarshalIndent(sample.ToSample(), "", "  ")
			if nil != err {
				return err
			}

			err = os.WriteFile(filePath, sampleJSON, 0644)
			if nil != err {
				return err
			}
		}

	}

	return nil
}
