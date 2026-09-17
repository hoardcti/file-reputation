package abusech

import (
	"github.com/hoardcti/file-reputation/internal/feed"
	"time"
)

// SourceName identifies abuse.ch's MalwareBazaar as a feed.Sample source.
const SourceName = "MalwareBazaar (abuse.ch)"

// ToSample translates a SampleInfo (from the get_info API) into the shared feed.Sample representation.
func (s SampleInfo) ToSample() feed.Sample {
	var lastSeen *time.Time
	if nil != s.LastSeen {
		t := s.LastSeen.Time()
		lastSeen = &t
	}

	codeSign := make([]feed.CodeSign, 0, len(s.CodeSign))
	for _, c := range s.CodeSign {
		codeSign = append(codeSign, feed.CodeSign{
			SubjectCN:    c.SubjectCN,
			IssuerCN:     c.IssuerCN,
			Algorithm:    c.Algorithm,
			ValidFrom:    c.ValidFrom,
			ValidTo:      c.ValidTo,
			SerialNumber: c.SerialNumber,
			CSCBListed:   c.CSCBListed,
			CSCBReason:   c.CSCBReason,
		})
	}

	yaraMatches := make([]feed.YARAMatch, 0, len(s.YARARules))
	for _, y := range s.YARARules {
		yaraMatches = append(yaraMatches, feed.YARAMatch{
			RuleName:    y.RuleName,
			Author:      y.Author,
			Description: y.Description,
			Reference:   y.Reference,
		})
	}

	comments := make([]feed.Comment, 0, len(s.Comments))
	for _, c := range s.Comments {
		comments = append(comments, feed.Comment{
			ID:            c.ID,
			DateAdded:     c.DateAdded,
			TwitterHandle: c.TwitterHandle,
			DisplayName:   c.DisplayName,
			Comment:       c.Comment,
		})
	}

	sha3384 := s.SHA3_384

	return feed.Sample{
		Hashes: feed.Hashes{
			SHA256:    s.SHA256,
			SHA1:      s.SHA1,
			MD5:       s.MD5,
			SHA3384:   &sha3384,
			TLSH:      s.TLSH,
			Imphash:   s.Imphash,
			Telfhash:  s.Telfhash,
			Gimphash:  s.Gimphash,
			SSDeep:    s.SSDeep,
			DhashIcon: s.DhashIcon,
		},
		Metadata: feed.Metadata{
			Names:           []string{s.FileName},
			MIMEType:        s.FileTypeMIME,
			Type:            s.FileType,
			Size:            s.FileSize,
			Format:          s.FileFormat,
			Arch:            s.FileArch,
			Magika:          s.Magika,
			TrID:            s.TrID,
			ArchivePW:       s.ArchivePW,
			FileInformation: s.FileInformation,
			OLEInformation:  s.OLEInformation,
		},
		Intelligence: feed.Intelligence{
			Signature:   s.Signature,
			Tags:        s.Tags,
			YARAMatches: yaraMatches,
			Comments:    comments,
			VendorIntel: s.VendorIntel,
		},
		Submission: feed.Submission{
			Reporter:       s.Reporter,
			Anonymous:      1 == s.Anonymous,
			OriginCountry:  s.OriginCountry,
			DeliveryMethod: s.DeliveryMethod,
		},
		CodeSign:  codeSign,
		Sources:   []string{SourceName},
		FirstSeen: s.FirstSeen.Time(),
		LastSeen:  lastSeen,
	}
}
