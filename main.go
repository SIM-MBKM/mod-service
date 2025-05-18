package main

import (
	"fmt"

	"github.com/SIM-MBKM/mod-service/src/helpers"
	"github.com/SIM-MBKM/mod-service/src/middleware"
	"github.com/gin-gonic/gin"
)

func main() {
	helpers.LoadEnv()
	secretKey := helpers.GetEnv("APP_KEY", "secret")

	expireSeconds := int64(99999)

	// Inisialisasi Gin
	r := gin.Default()

	r.Use(middleware.AccessKeyMiddleware(secretKey, expireSeconds))

	// Generate Key endpoint
	r.GET("/generate-key", func(c *gin.Context) {
		generator := helpers.NewSecurityAccessKey()
		accessKey, err := generator.GenerateAccessKey()

		if err != nil {
			c.JSON(500, gin.H{
				"error": fmt.Sprintf("Error generating access key: %v", err),
			})
			return
		}

		c.JSON(200, gin.H{
			"access_key": accessKey,
			"note":       "This key can be used with Laravel Security::decrypt()",
		})
	})

	r.GET("/secure-endpoint", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Authorized"})
	})

	r.Run(":8084")
}
