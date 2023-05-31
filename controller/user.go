package controller

import (
	"blog-api/database"
	"blog-api/model"
	"errors"
	"fmt"
	"html"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var privateKey = "jwttestkey"

func Register(c *gin.Context) {
	var login model.Authentication

	err := c.ShouldBindJSON(&login)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	hashedPassword, err := hashPassword(login.Password)

	if err != nil {
		fmt.Println("Error hashing password:", err)
	}

	user := model.User{
		Username: html.EscapeString(strings.TrimSpace(login.Username)),
		Password: string(hashedPassword),
	}

	if err := database.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User registered successfully"})
}

func Login(c *gin.Context) {
	var login model.Authentication

	err := c.ShouldBindJSON(&login)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	user, err := findUserByUsername(login.Username)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err = validatePassword(user.Password, login.Password)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}

	jwt, err := generateJWT(user)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"jwt": jwt})
}

func findUserByUsername(username string) (model.User, error) {
	var user model.User

	err := database.DB.Where("username=?", username).Find(&user).Error

	if err != nil {
		return model.User{}, err
	}

	return user, nil
}

func findUserByID(id uint) (model.User, error) {
	var user model.User

	err := database.DB.Preload("Posts").Where("ID=?", id).Find(&user).Error

	if err != nil {
		return model.User{}, err
	}

	return user, nil
}

func getActiveUser(c *gin.Context) (model.User, error) {
	token, err := getJwtToken(c)

	if err != nil {
		return model.User{}, err
	}

	err = validateJWT(token)

	if err != nil {
		return model.User{}, err
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	id := uint(claims["id"].(float64))

	user, err := findUserByID(id)

	if err != nil {
		return model.User{}, err
	}

	return user, nil
}

func hashPassword(password string) ([]byte, error) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if err != nil {
		return nil, err
	}

	return passwordHash, nil
}

func validatePassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
}

func generateJWT(user model.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"id":  user.ID,
		"iat": time.Now().Unix(),
		"eat": time.Now().Add(time.Second * time.Duration(86400)).Unix(),
	})

	return token.SignedString([]byte(privateKey))
}

func validateJWT(token *jwt.Token) error {
	_, ok := token.Claims.(jwt.MapClaims)
	if ok && token.Valid {
		return nil
	}

	return errors.New("invalid jwt")
}

func getJwtToken(c *gin.Context) (*jwt.Token, error) {
	bearer := c.Request.Header.Get("Authorization")
	splitToken := strings.Split(bearer, " ")
	token := ""

	if len(splitToken) == 2 {
		token = splitToken[1]
	}

	jwtToken, err := jwt.Parse(token, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", jwtToken.Header["alg"])
		}

		return []byte(privateKey), nil
	})

	return jwtToken, err
}

func JWTAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token, err := getJwtToken(c)

		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}

		err = validateJWT(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			c.Abort()
			return
		}
		c.Next()
	}
}
