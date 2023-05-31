package model

import (
	"time"

	"gorm.io/gorm"
)

type Authentication struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type User struct {
	gorm.Model
	Username string `gorm:"size:255;not null;unique" json:"username"`
	Password string `gorm:"size:255;not null;" json:"-"`
	Posts    []Post
}

type Post struct {
	gorm.Model
	Title        string `json:"title"`
	Author       string `json:"author"`
	Body         string `json:"body"`
	CreatedAt    time.Time
	LastModified time.Time
	DeletedAt    time.Time
	UserID       uint
}
