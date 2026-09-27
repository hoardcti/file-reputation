// Package feed defines hoardCTI's normalised file-reputation record, the JSON document written
// once per sample whatever source reported it.
//
// Package feed is internal: only this module can import it, so its exported names aren't a
// public API. It is kept apart from the source packages (currently only abusech) because it is
// the schema every source translates into, and the published files must stay identical across
// sources (GO-PKG-004 reason 4).
package feed

import (
	"encoding/json"
	"time"
)

// Sample is one file's reputation record. Every field is written to the published JSON file, so
// renaming a JSON key here changes the data format consumers depend on.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to choose the
// field's JSON key. omitzero leaves the field out of the output when it holds its zero value
// (nil for pointers, slices, maps and raw JSON).
type Sample struct {
	// Hashes holds every digest the source computed for the file.
	Hashes Hashes `json:"hashes"`

	// Metadata describes the file itself: names, type and size.
	Metadata Metadata `json:"file_metadata"`

	// Intelligence holds the source's verdicts about the file.
	Intelligence Intelligence `json:"intelligence"`

	// Submission records who reported the file to the source.
	Submission Submission `json:"submission"`

	// CodeSign lists the code-signing certificates attached to the file; omitted when unsigned.
	CodeSign []CodeSign `json:"code_sign,omitzero"`

	// Sources names every feed that reported the file.
	Sources []string `json:"sources"`

	// FirstSeen is when the source first saw the file, in UTC.
	FirstSeen time.Time `json:"first_seen"`

	// LastSeen is when the source last saw the file, in UTC. It's nil when the source has only
	// one sighting, which is different from the zero time.
	LastSeen *time.Time `json:"last_seen"`
}

// Metadata describes a file independently of any verdict about it.
type Metadata struct {
	// Names are the file names the file was reported under.
	Names []string `json:"names"`

	// MIMEType is the file's detected MIME type, such as "application/x-dosexec".
	MIMEType string `json:"mime_type"`

	// Type is the source's short file type, such as "exe".
	Type string `json:"type"`

	// Size is the file's size in bytes.
	Size int64 `json:"size"`

	// Format is the executable or document format, such as "PE32"; nil when unknown.
	Format *string `json:"format"`

	// Architecture is the CPU architecture the file targets, such as "i386"; nil when unknown.
	Architecture *string `json:"arch"`

	// Information is free-text detail about the file; nil when the source gives none.
	Information *string `json:"info"`

	// Magika is Google Magika's content-type label for the file; nil when not computed.
	Magika *string `json:"magika"`

	// TrID is the TrID file identifier's output, passed through as raw JSON because the source
	// sends either a list of matches or the string "n/a".
	TrID json.RawMessage `json:"trid,omitzero"`

	// ArchivePassword is the password of the archive the file is distributed in. It's nil when
	// the source gives none.
	ArchivePassword *string `json:"archive_pw,omitzero"`

	// FileInformation is contextual detail about the file, passed through as raw JSON because
	// its shape varies by file type.
	FileInformation json.RawMessage `json:"file_information,omitzero"`

	// OLEInformation is oletools output for Office documents, passed through as raw JSON: an
	// object when present and an empty list otherwise.
	OLEInformation json.RawMessage `json:"ole_information,omitzero"`
}

// Hashes holds the digests and fuzzy hashes of a file. Every value is hex or the hash tool's
// native text encoding.
type Hashes struct {
	// SHA256 is the file's SHA-256 digest; always present, and the published file's name.
	SHA256 string `json:"sha256"`

	// SHA1 is the file's SHA-1 digest.
	SHA1 string `json:"sha1"`

	// MD5 is the file's MD5 digest.
	MD5 string `json:"md5"`

	// SHA3_384 is the file's SHA3-384 digest. It's nil when the source doesn't compute one.
	SHA3_384 *string `json:"sha3_384,omitzero"` //nolint:revive,staticcheck // GO-NAM-003: digits after an initialism.

	// TLSH is the file's TLSH fuzzy hash; nil when not computed.
	TLSH *string `json:"tlsh"`

	// Imphash is the hash of a PE file's import table; nil for other file types.
	Imphash *string `json:"imphash"`

	// Telfhash is the symbol-table hash of an ELF file; nil for other file types.
	Telfhash *string `json:"telfhash"`

	// Gimphash is the import hash of a Go binary; nil for other file types.
	Gimphash *string `json:"gimphash"`

	// SSDeep is the file's ssdeep fuzzy hash; nil when not computed.
	SSDeep *string `json:"ssdeep"`

	// DhashIcon is the perceptual hash of the file's icon; nil when it has none.
	DhashIcon *string `json:"dhash_icon,omitzero"`
}

// Intelligence holds a source's verdicts and analyst notes about a file.
type Intelligence struct {
	// Signature is the malware family the source attributes the file to; nil when unknown.
	Signature *string `json:"signature"`

	// Tags are the source's free-text labels for the file.
	Tags []string `json:"tags"`

	// YARAMatches lists the YARA rules that matched the file; omitted when none did.
	YARAMatches []YARAMatch `json:"yara_rules,omitzero"`

	// Comments are notes left on the file by the source's users; omitted when there are none.
	Comments []Comment `json:"comments,omitzero"`

	// VendorIntel holds third-party analysis results keyed by vendor name. Each vendor's result
	// has its own shape, so it's passed through as raw JSON. It's omitted when no vendor
	// reported anything.
	VendorIntel map[string]json.RawMessage `json:"vendor_intel,omitzero"`
}

// Submission describes how and by whom a file was reported to its source.
type Submission struct {
	// Reporter is the account that reported the file.
	Reporter string `json:"reporter"`

	// Anonymous reports whether the reporter asked to stay anonymous.
	Anonymous bool `json:"anonymous"`

	// OriginCountry is the two-letter country code the file was submitted from; nil when
	// unknown.
	OriginCountry *string `json:"origin_country,omitzero"`

	// DeliveryMethod is how the file reached its victim, such as "email_attachment"; nil when
	// unknown.
	DeliveryMethod *string `json:"delivery_method,omitzero"`
}

// CodeSign describes an Authenticode or other code-signing certificate attached to a file. Every
// field is nil when the source couldn't read it from the certificate.
type CodeSign struct {
	// SubjectCN is the common name of the certificate's subject.
	SubjectCN *string `json:"subject_cn"`

	// IssuerCN is the common name of the certificate authority that issued it.
	IssuerCN *string `json:"issuer_cn"`

	// Algorithm is the signature algorithm, such as "sha256WithRSAEncryption".
	Algorithm *string `json:"algorithm"`

	// ValidFrom is the start of the certificate's validity period, as the source wrote it.
	ValidFrom *string `json:"valid_from"`

	// ValidTo is the end of the certificate's validity period, as the source wrote it.
	ValidTo *string `json:"valid_to"`

	// SerialNumber is the certificate's serial number in hex.
	SerialNumber *string `json:"serial_number"`

	// CSCBListed reports whether the certificate is on the Code Signing Certificate Blocklist.
	CSCBListed *bool `json:"cscb_listed"`

	// CSCBReason is why the certificate is on the blocklist.
	CSCBReason *string `json:"cscb_reason"`
}

// YARAMatch describes one YARA rule that matched a file.
type YARAMatch struct {
	// RuleName is the name of the rule that matched.
	RuleName string `json:"rule_name"`

	// Author is who wrote the rule; nil when unknown.
	Author *string `json:"author"`

	// Description is the rule author's summary of what it detects; nil when absent.
	Description *string `json:"description"`

	// Reference is a URL or citation for the rule. It's published, never fetched.
	Reference *string `json:"reference"`
}

// Comment is a note a source's user left on a file.
type Comment struct {
	// ID identifies the comment within the source.
	ID string `json:"id"`

	// DateAdded is when the comment was written, as the source formatted it.
	DateAdded string `json:"date_added"`

	// TwitterHandle is the commenter's Twitter handle; nil when they didn't give one.
	TwitterHandle *string `json:"twitter_handle"`

	// DisplayName is the commenter's display name; nil when they didn't give one.
	DisplayName *string `json:"display_name"`

	// Comment is the text of the comment.
	Comment string `json:"comment"`
}
