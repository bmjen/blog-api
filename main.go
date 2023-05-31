package main

import (
	"log"

	"blog-api/controller"
	"blog-api/database"
	"blog-api/model"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load(".env.local")
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	database.Connect()
	database.DB.AutoMigrate(&model.User{}, &model.Post{})

	r := gin.Default()

	auth := r.Group("/auth")
	auth.POST("/register", controller.Register)
	auth.POST("/login", controller.Login)

	api := r.Group("/api/v1")
	{
		api.Use(controller.JWTAuthMiddleware())
		api.GET("/posts", controller.GetPosts)
		api.GET("/posts/:id", controller.GetPost)
		api.POST("/posts", controller.CreatePost)
		api.PUT("/posts/:id", controller.UpdatePost)
		api.DELETE("/posts/:id", controller.DeletePost)
	}

	r.Run(":8080")
}
