package main

import (
	"gin-api/middleware"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	validator := middleware.NewJWTValidator(
		"http://10.100.1.236:8080/realms/local",
		"user",
	)

	AuthMiddleware := validator.MiddlewareWithScope("user.api")

	authorized := r.Group("/api")
	authorized.Use(AuthMiddleware)

	authorized.GET("/protected", func(c *gin.Context) {
		userID := c.GetString("user_id")
		email := c.GetString("email")
		c.JSON(200, gin.H{"user_id": userID, "email": email})
	})

	r.Run(":8082")
}
