package feed

import (
	"encoding/json"
	"time"
)

type Sample struct {
	Hashes Hashes `json:"hashes"`

	Metadata     Metadata     `json:"file_metadata"`
	Intelligence Intelligence `json:"intelligence"`
	Submission   Submission   `json:"submission"`

	CodeSign []CodeSign `json:"code_sign,omitempty"`

	Sources   []string   `json:"sources"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  *time.Time `json:"last_seen"`
}

type Metadata struct {
	Names     []string        `json:"names"`
	MIMEType  string          `json:"mime_type"`
	Type      string          `json:"type"`
	Size      int64           `json:"size"`
	Format    *string         `json:"format"`
	Arch      *string         `json:"arch"`
	Info      *string         `json:"info"`
	Magika    *string         `json:"magika"`
	TrID      json.RawMessage `json:"trid,omitempty"` // shape varies: array of matches or "n/a"
	ArchivePW *string         `json:"archive_pw,omitempty"`

	// FileInformation holds contextual info about the sample; its shape
	// varies by file type.
	FileInformation json.RawMessage `json:"file_information,omitempty"`

	// OLEInformation holds oletools output for Office document samples;
	// it's an object when present and an empty array otherwise.
	OLEInformation json.RawMessage `json:"ole_information,omitempty"`
}

type Hashes struct {
	SHA256    string  `json:"sha256"`
	SHA1      string  `json:"sha1"`
	MD5       string  `json:"md5"`
	SHA3384   *string `json:"sha3_384,omitempty"`
	TLSH      *string `json:"tlsh"`
	Imphash   *string `json:"imphash"`
	Telfhash  *string `json:"telfhash"`
	Gimphash  *string `json:"gimphash"`
	SSDeep    *string `json:"ssdeep"`
	DhashIcon *string `json:"dhash_icon,omitempty"`
}

type Intelligence struct {
	Signature   *string     `json:"signature"`
	Tags        []string    `json:"tags"`
	YARAMatches []YARAMatch `json:"yara_rules,omitempty"`
	Comments    []Comment   `json:"comments,omitempty"`

	// VendorIntel holds third-party reputation/analysis blobs keyed by
	// vendor name; each vendor's shape differs, so it is passed through raw.
	VendorIntel map[string]json.RawMessage `json:"vendor_intel,omitempty"`
}

// Submission describes how and by whom a sample was reported to the source feed.
type Submission struct {
	Reporter       string  `json:"reporter"`
	Anonymous      bool    `json:"anonymous"`
	OriginCountry  *string `json:"origin_country,omitempty"`
	DeliveryMethod *string `json:"delivery_method,omitempty"`
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

// YARAMatch represents a YARA rule match triggered by the sample.
type YARAMatch struct {
	RuleName    string  `json:"rule_name"`
	Author      *string `json:"author"`
	Description *string `json:"description"`
	Reference   *string `json:"reference"`
}

// Comment represents a user comment left on a sample in the source feed.
type Comment struct {
	ID            string  `json:"id"`
	DateAdded     string  `json:"date_added"`
	TwitterHandle *string `json:"twitter_handle"`
	DisplayName   *string `json:"display_name"`
	Comment       string  `json:"comment"`
}
