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
func AccessKeyMiddleware(security *helpers.Security, secretKey string, expireSeconds int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Ambil Access-Key dari header
		accessKey := c.GetHeader("Access-Key")
		if accessKey == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Tidak ada otorisasi service"})
			c.Abort()
			return
		}
		// Dekripsi Access-Key
		decryptedKey, err := security.Decrypt(accessKey)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Tidak ada otorisasi service"})
			c.Abort()
			return
		}
		// Lakukan type assertion ke string
		decryptedKeyStr, ok := decryptedKey.(string)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Format kunci tidak valid"})
			c.Abort()
			return
		}

		// Pisahkan secretKey dan timestamp
		parts := strings.Split(decryptedKeyStr, "@")
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
