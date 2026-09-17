package abusech

import (
	"encoding/json"
	"strings"
	"time"
)

// abuseTimeLayout matches the non-RFC3339 timestamps abuse.ch's export dump
// returns, e.g. "2026-09-17 14:18:01 UTC". The get_info API omits the zone,
// e.g. "2026-09-17 14:18:01" (see abuseTimeLayoutNoZone); abuse.ch documents
// both as UTC.
const abuseTimeLayout = "2006-01-02 15:04:05 MST"
const abuseTimeLayoutNoZone = "2006-01-02 15:04:05"

// AbuseTime wraps time.Time to parse abuse.ch's timestamp format.
type AbuseTime time.Time

// UnmarshalJSON implements the json.Unmarshaler interface for AbuseTime.
func (t *AbuseTime) UnmarshalJSON(data []byte) error {
	s := strings.Trim(string(data), `"`)
	if "" == s || "null" == s {
		*t = AbuseTime(time.Time{})
		return nil
	}
	parsed, err := time.Parse(abuseTimeLayout, s)
	if nil != err {
		parsed, err = time.ParseInLocation(abuseTimeLayoutNoZone, s, time.UTC)
		if nil != err {
			return err
		}
	}
	*t = AbuseTime(parsed)
	return nil
}

// Time returns the AbuseTime as a standard time.Time.
func (t AbuseTime) Time() time.Time {
	return time.Time(t)
}

// GetInfoResponse represents the JSON structure returned by abuse.ch's
// MalwareBazaar get_info API (POST query=get_info).
type GetInfoResponse struct {
	QueryStatus string       `json:"query_status"`
	Data        []SampleInfo `json:"data,omitempty"`
}

// SampleInfo represents a single sample's details as returned by get_info.
type SampleInfo struct {
	SHA256          string                     `json:"sha256_hash"`
	SHA3_384        string                     `json:"sha3_384_hash"`
	SHA1            string                     `json:"sha1_hash"`
	MD5             string                     `json:"md5_hash"`
	FirstSeen       AbuseTime                  `json:"first_seen"`
	LastSeen        *AbuseTime                 `json:"last_seen"`
	FileName        string                     `json:"file_name"`
	FileSize        int64                      `json:"file_size"`
	FileTypeMIME    string                     `json:"file_type_mime"`
	FileType        string                     `json:"file_type"`
	FileFormat      *string                    `json:"file_format"`
	FileArch        *string                    `json:"file_arch"`
	Reporter        string                     `json:"reporter"`
	OriginCountry   *string                    `json:"origin_country"`
	Anonymous       int                        `json:"anonymous"`
	Signature       *string                    `json:"signature"`
	Imphash         *string                    `json:"imphash"`
	TLSH            *string                    `json:"tlsh"`
	Telfhash        *string                    `json:"telfhash"`
	Gimphash        *string                    `json:"gimphash"`
	SSDeep          *string                    `json:"ssdeep"`
	Magika          *string                    `json:"magika"`
	DhashIcon       *string                    `json:"dhash_icon"`
	TrID            json.RawMessage            `json:"trid,omitempty"` // shape varies: array of matches or "n/a"
	Tags            []string                   `json:"tags"`
	ArchivePW       *string                    `json:"archive_pw"`
	CodeSign        []CodeSign                 `json:"code_sign,omitempty"`
	DeliveryMethod  *string                    `json:"delivery_method"`
	FileInformation json.RawMessage            `json:"file_information,omitempty"` // shape varies by file type
	YARARules       []YARARule                 `json:"yara_rules,omitempty"`
	OLEInformation  json.RawMessage            `json:"ole_information,omitempty"` // shape varies: object for Office samples, [] otherwise
	VendorIntel     map[string]json.RawMessage `json:"vendor_intel,omitempty"`    // shape varies by vendor
	Comments        []Comment                  `json:"comments,omitempty"`
}

// CodeSign represents an authenticode/code-signing certificate attached to a sample.
type CodeSign struct {
	SubjectCN    *string `json:"subject_cn"`
	IssuerCN     *string `json:"issuer_cn"`
	Algorithm    *string `json:"algorithm"`
	ValidFrom    *string `json:"valid_from"`
	ValidTo      *string `json:"valid_to"`
	SerialNumber *string `json:"serial_number"`
	CSCBListed   *bool   `json:"cscb_listed"`
	CSCBReason   *string `json:"cscb_reason"`
}

// YARARule represents a YARA rule match triggered by the sample.
type YARARule struct {
	RuleName    string  `json:"rule_name"`
	Author      *string `json:"author"`
	Description *string `json:"description"`
	Reference   *string `json:"reference"`
}

// Comment represents a MalwareBazaar user comment left on a sample.
type Comment struct {
	ID            string  `json:"id"`
	DateAdded     string  `json:"date_added"`
	TwitterHandle *string `json:"twitter_handle"`
	DisplayName   *string `json:"display_name"`
	Comment       string  `json:"comment"`
}
