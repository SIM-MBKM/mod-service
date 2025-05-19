package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SIM-MBKM/mod-service/src/helpers"

	"github.com/gin-gonic/gin"
)

// AccessKeyMiddleware validates the Access-Key in the request header
func AccessKeyMiddleware(secretKey string, expireSeconds int64) gin.HandlerFunc {
	return func(c *gin.Context) {

		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, Access-Key")
		c.Header("Access-Control-Allow-Methods", "POST, HEAD, PATCH, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(204)
			return
		}

		// Ambil Access-Key dari header
		accessKey := c.GetHeader("Access-Key")
		if accessKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Tidak ada otorisasi service"})
			c.Abort()
			return
		}

		security := helpers.NewSecurityAccessKey()
		decryptedKey, err := security.Decrypt(accessKey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Tidak ada otorisasi service"})
			c.Abort()
			return
		}

		// Pisahkan secretKey dan timestamp
		parts := strings.Split(decryptedKey, "@")
		if len(parts) != 2 || parts[0] != secretKey {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Tidak ada otorisasi service"})
			c.Abort()
			return
		}

		// Validasi waktu dengan mengonversi timestamp string ke int64
		requestTimestamp, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Tidak ada otorisasi service"})
			c.Abort()
			return
		}

		// Waktu saat ini dalam bentuk Unix timestamp
		currentTimestamp := time.Now().Unix()

		// Periksa apakah waktu request sudah lewat atau jika waktu sekarang terlalu jauh dari waktu request
		if requestTimestamp > currentTimestamp || currentTimestamp-requestTimestamp > expireSeconds {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Tidak ada otorisasi service"})
			c.Abort()
			return
		}
		// Lanjut ke handler berikutnya
		c.Next()
	}
}
