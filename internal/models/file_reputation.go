package models

import (
	"time"

	"gorm.io/gorm"
)

type FileReputation struct {
	ID        uint   `gorm:"primaryKey"`
	Hash      string `gorm:"uniqueIndex;size:64;not null"` // e.g. SHA-256
	Verdict   string `gorm:"index;size:32"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

func (FileReputation) TableName() string { return "file_reputations" }
