package main

import (
	"fmt"

	"github.com/SIM-MBKM/mod-service/src/helpers"
	"github.com/SIM-MBKM/mod-service/src/middleware"
	"github.com/SIM-MBKM/mod-service/src/service"

	"github.com/gin-gonic/gin"
)

func main() {
	helpers.LoadEnv()
	secretKey := helpers.GetEnv("APP_KEY", "secret")

	// Konfigurasi middleware
	security := helpers.NewSecurity("sha256", secretKey, "aes")
	expireSeconds := int64(9999)

	// Inisialisasi Gin
	r := gin.Default()

	// Tambahkan middleware
	r.Use(middleware.AccessKeyMiddleware(security, secretKey, expireSeconds))

	authService := service.NewAuthService("http://localhost:8082", []string{"/async"})

	opts := map[string]interface{}{
		"username": "admin",
		"password": "test",
	}

	res, err := authService.Service.Request("POST", "login", opts)

	if err != nil {
		panic(err)
	}

	fmt.Println(res)

	r.GET("/secure-endpoint", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "Authorized"})
	})

	r.Run(":8084")
}
