package controller

import (
	"blog-api/database"
	"blog-api/model"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

func GetPosts(c *gin.Context) {
	user, err := getActiveUser(c)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": user.Posts})
}

func GetPost(c *gin.Context) {
	fmt.Println("Getting Post")
}

func CreatePost(c *gin.Context) {
	var post model.Post

	err := c.ShouldBindJSON(&post)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := getActiveUser(c)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	post.UserID = user.ID
	post.Author = user.Username

	err = database.DB.Create(&post).Error

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"data": post})
}

func UpdatePost(c *gin.Context) {
	fmt.Println("Updating Post")
}

func DeletePost(c *gin.Context) {
	fmt.Println("Deleting Post")
}
