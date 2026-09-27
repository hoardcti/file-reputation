package abusech

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hoardcti/file-reputation/internal/feed"
)

const (
	// ABUSE_TIME_LAYOUT matches the timestamps in abuse.ch's export dump, such as
	// "2026-09-17 14:18:01 UTC".
	ABUSE_TIME_LAYOUT = "2006-01-02 15:04:05 MST"

	// ABUSE_TIME_LAYOUT_WITHOUT_ZONE matches the get_info API's timestamps, such as
	// "2026-09-17 14:18:01". abuse.ch documents them as UTC.
	ABUSE_TIME_LAYOUT_WITHOUT_ZONE = time.DateTime

	// SOURCE_NAME identifies MalwareBazaar in the Sources list of every feed.Sample it produces.
	SOURCE_NAME = "MalwareBazaar (abuse.ch)"
)

// AbuseTime is a timestamp in one of abuse.ch's non-RFC 3339 layouts. It exists only to decode
// them; convert it to time.Time straight away.
type AbuseTime time.Time

// UnmarshalJSON parses an abuse.ch timestamp in either documented layout, as UTC. A JSON null or
// an empty string leaves the zero time. It returns an error quoting the input when neither layout
// matches.
//
// It has a pointer receiver (*AbuseTime) so it can change the value it's called on;
// encoding/json calls it for every AbuseTime field it decodes.
func (timestamp *AbuseTime) UnmarshalJSON(data []byte) error {
	// abuse.ch sends null or "" for timestamps it doesn't have; both mean "not set".
	text := strings.Trim(string(data), `"`)
	if "" == text || "null" == text {
		*timestamp = AbuseTime(time.Time{})
		return nil
	}

	// Try the layout with a zone first, then fall back to the zoneless get_info layout.
	parsed, err := time.Parse(ABUSE_TIME_LAYOUT, text)
	if nil != err {
		parsed, err = time.ParseInLocation(ABUSE_TIME_LAYOUT_WITHOUT_ZONE, text, time.UTC)
	}
	if nil != err {
		return fmt.Errorf("parsing abuse.ch timestamp %q: %w", text, err)
	}

	*timestamp = AbuseTime(parsed.UTC())
	return nil
}

// GetInfoResponse mirrors the JSON body of MalwareBazaar's get_info query (POST query=get_info).
// Its field names follow the upstream API exactly.
//
// The text in back-quotes after each field is a struct tag: encoding/json reads it to find the
// field's JSON key in the upstream response.
type GetInfoResponse struct {
	// QueryStatus is "ok" when the hash is known, or a reason such as "hash_not_found".
	QueryStatus string `json:"query_status"`

	// Data holds the sample's details. It's empty unless QueryStatus is "ok".
	Data []SampleInfo `json:"data"`
}

// SampleInfo mirrors one sample in a get_info response. Pointer fields are nil when the upstream
// sends null.
type SampleInfo struct {
	// SHA256 is the sample's SHA-256 digest.
	SHA256 string `json:"sha256_hash"`

	// SHA3_384 is the sample's SHA3-384 digest; empty when the upstream didn't compute it.
	SHA3_384 string `json:"sha3_384_hash"` //nolint:revive,staticcheck // GO-NAM-003: digits after an initialism.

	// SHA1 is the sample's SHA-1 digest.
	SHA1 string `json:"sha1_hash"`

	// MD5 is the sample's MD5 digest.
	MD5 string `json:"md5_hash"`

	// FirstSeen is when MalwareBazaar first received the sample.
	FirstSeen AbuseTime `json:"first_seen"`

	// LastSeen is when MalwareBazaar last received the sample; nil after a single sighting.
	LastSeen *AbuseTime `json:"last_seen"`

	// FileName is the name the sample was submitted under.
	FileName string `json:"file_name"`

	// FileSize is the sample's size in bytes.
	FileSize int64 `json:"file_size"`

	// FileTypeMIME is the sample's detected MIME type.
	FileTypeMIME string `json:"file_type_mime"`

	// FileType is MalwareBazaar's short file type, such as "exe".
	FileType string `json:"file_type"`

	// FileFormat is the executable or document format, such as "PE32".
	FileFormat *string `json:"file_format"`

	// FileArchitecture is the CPU architecture the sample targets.
	FileArchitecture *string `json:"file_arch"`

	// Reporter is the account that submitted the sample.
	Reporter string `json:"reporter"`

	// OriginCountry is the two-letter country code the sample was submitted from.
	OriginCountry *string `json:"origin_country"`

	// Anonymous is 1 when the reporter asked to stay anonymous and 0 otherwise.
	Anonymous int `json:"anonymous"`

	// Signature is the malware family MalwareBazaar attributes the sample to.
	Signature *string `json:"signature"`

	// Imphash is the hash of a PE sample's import table.
	Imphash *string `json:"imphash"`

	// TLSH is the sample's TLSH fuzzy hash.
	TLSH *string `json:"tlsh"`

	// Telfhash is the symbol-table hash of an ELF sample.
	Telfhash *string `json:"telfhash"`

	// Gimphash is the import hash of a Go sample.
	Gimphash *string `json:"gimphash"`

	// SSDeep is the sample's ssdeep fuzzy hash.
	SSDeep *string `json:"ssdeep"`

	// Magika is Google Magika's content-type label for the sample.
	Magika *string `json:"magika"`

	// DhashIcon is the perceptual hash of the sample's icon.
	DhashIcon *string `json:"dhash_icon"`

	// TrID is kept as raw JSON: the upstream sends a list of matches or the string "n/a".
	TrID json.RawMessage `json:"trid"`

	// Tags are MalwareBazaar's free-text labels for the sample.
	Tags []string `json:"tags"`

	// ArchivePassword is the password of the archive the sample is distributed in.
	ArchivePassword *string `json:"archive_pw"`

	// CodeSign lists the sample's code-signing certificates.
	CodeSign []CodeSign `json:"code_sign"`

	// DeliveryMethod is how the sample reached its victim, such as "email_attachment".
	DeliveryMethod *string `json:"delivery_method"`

	// FileInformation is kept as raw JSON because its shape varies by file type.
	FileInformation json.RawMessage `json:"file_information"`

	// YARARules lists the YARA rules that matched the sample.
	YARARules []YARARule `json:"yara_rules"`

	// OLEInformation is kept as raw JSON: an object for Office samples and [] otherwise.
	OLEInformation json.RawMessage `json:"ole_information"`

	// VendorIntel holds third-party results keyed by vendor name, each kept as raw JSON because
	// every vendor uses its own shape.
	VendorIntel map[string]json.RawMessage `json:"vendor_intel"`

	// Comments are notes MalwareBazaar users left on the sample.
	Comments []Comment `json:"comments"`
}

// ToSample translates the upstream sample into hoardCTI's normalised feed.Sample.
//
// Empty upstream lists and maps become nil, so the omitzero fields in feed.Sample leave them out
// of the published JSON, exactly as earlier versions of this module did.
func (info SampleInfo) ToSample() feed.Sample {
	// A nil LastSeen means a single sighting, which must stay distinct from the zero time.
	var lastSeen *time.Time
	if nil != info.LastSeen {
		lastSeen = new(time.Time(*info.LastSeen).UTC())
	}

	// The upstream sends {} when no vendor reported anything. Collapse that to nil so omitzero
	// leaves the field out, as the published format always has.
	vendorIntel := info.VendorIntel
	if 0 == len(vendorIntel) {
		vendorIntel = nil
	}

	return feed.Sample{
		Hashes: feed.Hashes{
			SHA256:    info.SHA256,
			SHA1:      info.SHA1,
			MD5:       info.MD5,
			SHA3_384:  new(info.SHA3_384),
			TLSH:      info.TLSH,
			Imphash:   info.Imphash,
			Telfhash:  info.Telfhash,
			Gimphash:  info.Gimphash,
			SSDeep:    info.SSDeep,
			DhashIcon: info.DhashIcon,
		},
		Metadata: feed.Metadata{
			Names:           []string{info.FileName},
			MIMEType:        info.FileTypeMIME,
			Type:            info.FileType,
			Size:            info.FileSize,
			Format:          info.FileFormat,
			Architecture:    info.FileArchitecture,
			Magika:          info.Magika,
			TrID:            info.TrID,
			ArchivePassword: info.ArchivePassword,
			FileInformation: info.FileInformation,
			OLEInformation:  info.OLEInformation,
		},
		Intelligence: feed.Intelligence{
			Signature:   info.Signature,
			Tags:        info.Tags,
			YARAMatches: translateYARARules(info.YARARules),
			Comments:    translateComments(info.Comments),
			VendorIntel: vendorIntel,
		},
		Submission: feed.Submission{
			Reporter:       info.Reporter,
			Anonymous:      1 == info.Anonymous,
			OriginCountry:  info.OriginCountry,
			DeliveryMethod: info.DeliveryMethod,
		},
		CodeSign:  translateCodeSigns(info.CodeSign),
		Sources:   []string{SOURCE_NAME},
		FirstSeen: time.Time(info.FirstSeen).UTC(),
		LastSeen:  lastSeen,
	}
}

// CodeSign mirrors one code-signing certificate in a get_info response.
type CodeSign struct {
	// SubjectCN is the common name of the certificate's subject.
	SubjectCN *string `json:"subject_cn"`

	// IssuerCN is the common name of the issuing certificate authority.
	IssuerCN *string `json:"issuer_cn"`

	// Algorithm is the signature algorithm.
	Algorithm *string `json:"algorithm"`

	// ValidFrom is the start of the validity period, as the upstream formats it.
	ValidFrom *string `json:"valid_from"`

	// ValidTo is the end of the validity period, as the upstream formats it.
	ValidTo *string `json:"valid_to"`

	// SerialNumber is the certificate's serial number in hex.
	SerialNumber *string `json:"serial_number"`

	// CSCBListed reports whether the certificate is on the Code Signing Certificate Blocklist.
	CSCBListed *bool `json:"cscb_listed"`

	// CSCBReason is why the certificate is on the blocklist.
	CSCBReason *string `json:"cscb_reason"`
}

// YARARule mirrors one YARA rule match in a get_info response.
type YARARule struct {
	// RuleName is the name of the rule that matched.
	RuleName string `json:"rule_name"`

	// Author is who wrote the rule.
	Author *string `json:"author"`

	// Description is the rule author's summary of what it detects.
	Description *string `json:"description"`

	// Reference is a URL or citation for the rule. It's published, never fetched.
	Reference *string `json:"reference"`
}

// Comment mirrors one user comment in a get_info response.
type Comment struct {
	// ID identifies the comment within MalwareBazaar.
	ID string `json:"id"`

	// DateAdded is when the comment was written, as the upstream formats it.
	DateAdded string `json:"date_added"`

	// TwitterHandle is the commenter's Twitter handle.
	TwitterHandle *string `json:"twitter_handle"`

	// DisplayName is the commenter's display name.
	DisplayName *string `json:"display_name"`

	// Comment is the text of the comment.
	Comment string `json:"comment"`
}

// translateYARARules converts upstream YARA matches into feed.YARAMatch values. It returns nil
// for an empty list.
func translateYARARules(rules []YARARule) []feed.YARAMatch {
	// A nil slice is Go's empty list; append allocates on first use.
	var matches []feed.YARAMatch
	for _, rule := range rules {
		matches = append(matches, feed.YARAMatch{
			RuleName:    rule.RuleName,
			Author:      rule.Author,
			Description: rule.Description,
			Reference:   rule.Reference,
		})
	}

	return matches
}

// translateComments converts upstream comments into feed.Comment values. It returns nil for an
// empty list.
func translateComments(comments []Comment) []feed.Comment {
	var translated []feed.Comment
	for _, comment := range comments {
		translated = append(translated, feed.Comment{
			ID:            comment.ID,
			DateAdded:     comment.DateAdded,
			TwitterHandle: comment.TwitterHandle,
			DisplayName:   comment.DisplayName,
			Comment:       comment.Comment,
		})
	}

	return translated
}

// translateCodeSigns converts upstream certificates into feed.CodeSign values. It returns nil for
// an empty list.
func translateCodeSigns(certificates []CodeSign) []feed.CodeSign {
	var translated []feed.CodeSign
	for _, certificate := range certificates {
		translated = append(translated, feed.CodeSign{
			SubjectCN:    certificate.SubjectCN,
			IssuerCN:     certificate.IssuerCN,
			Algorithm:    certificate.Algorithm,
			ValidFrom:    certificate.ValidFrom,
			ValidTo:      certificate.ValidTo,
			SerialNumber: certificate.SerialNumber,
			CSCBListed:   certificate.CSCBListed,
			CSCBReason:   certificate.CSCBReason,
		})
	}

	return translated
}
