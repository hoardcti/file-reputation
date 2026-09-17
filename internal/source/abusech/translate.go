package abusech

import (
	"github.com/hoardcti/file-reputation/internal/feed"
	"time"
)

// SourceName identifies abuse.ch's MalwareBazaar as a feed.Sample source.
const SourceName = "MalwareBazaar (abuse.ch)"

// ToSample translates a DumpEntry into the shared feed.Sample representation.
func (e DumpEntry) ToSample() feed.Sample {
	tags := make([]string, 0, len(e.Tags))
	for _, t := range e.Tags {
		tags = append(tags, t.Tag)
	}

	var lastSeen *time.Time
	if e.LastSeen != nil {
		t := e.LastSeen.Time()
		lastSeen = &t
	}

	return feed.Sample{
		Hashes: feed.Hashes{
			SHA256:   e.SHA256,
			SHA1:     e.SHA1,
			MD5:      e.MD5,
			TLSH:     e.TLSH,
			Imphash:  e.Imphash,
			Telfhash: e.Telfhash,
			Gimphash: e.Gimphash,
			SSDeep:   e.SSDeep,
		},
		Metadata: feed.Metadata{
			Names:    []string{e.FileName},
			MIMEType: e.MIMEType,
			Type:     e.FileType,
			Size:     e.FileSize,
			Format:   e.FileFormat,
			Arch:     e.FileArch,
			Info:     e.FileInfo,
			Magika:   e.Magika,
		},
		Intelligence: feed.Intelligence{
			Signature: e.Signature,
			Tags:      tags,
		},
		Sources:   []string{SourceName},
		FirstSeen: e.FirstSeen.Time(),
		LastSeen:  lastSeen,
	}
}
