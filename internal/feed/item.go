package feed

import "time"

type Sample struct {
	Hashes Hashes `json:"hashes"`

	Metadata     Metadata     `json:"file_metadata"`
	Intelligence Intelligence `json:"intelligence"`

	Sources   []string   `json:"sources"`
	FirstSeen time.Time  `json:"first_seen"`
	LastSeen  *time.Time `json:"last_seen"`
}

type Metadata struct {
	Names    []string `json:"names"`
	MIMEType string   `json:"mime_type"`
	Type     string   `json:"type"`
	Size     int64    `json:"size"`
	Format   *string  `json:"format"`
	Arch     *string  `json:"arch"`
	Info     *string  `json:"info"`
	Magika   *string  `json:"magika"`
}

type Hashes struct {
	SHA256   string  `json:"sha256"`
	SHA1     string  `json:"sha1"`
	MD5      string  `json:"md5"`
	TLSH     *string `json:"tlsh"`
	Imphash  *string `json:"imphash"`
	Telfhash *string `json:"telfhash"`
	Gimphash *string `json:"gimphash"`
	SSDeep   *string `json:"ssdeep"`
}

type Intelligence struct {
	Signature *string  `json:"signature"`
	Tags      []string `json:"tags"`
}
