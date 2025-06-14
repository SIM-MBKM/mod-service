package middleware

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/SIM-MBKM/mod-service/src/helpers"

	"github.com/gin-gonic/gin"
)

// FrontendConfig holds configuration for frontend request detection
type FrontendConfig struct {
	AllowedOrigins    []string
	AllowedReferers   []string
	RequireOrigin     bool
	BypassForBrowsers bool
	CustomHeader      string
	CustomHeaderValue string
}

// AccessKeyMiddleware validates the Access-Key in the request header
func AccessKeyMiddleware(secretKey string, expireSeconds int64, frontendConfig *FrontendConfig) gin.HandlerFunc {
	return func(c *gin.Context) {

		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With, Access-Key")
		c.Header("Access-Control-Allow-Methods", "POST, HEAD, PATCH, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(204)
			return
		}

		// BYPASS ACCESS KEY UNTUK FRONTEND REQUESTS (jika dikonfigurasi)
		if frontendConfig != nil && isFrontendRequest(c, frontendConfig) {
			// Log untuk debugging (opsional)
			// fmt.Println("Frontend request detected, bypassing access key validation")
			c.Next()
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

func isFrontendRequest(c *gin.Context, config *FrontendConfig) bool {
	// CHECK 1: Custom header (highest priority)
	if config.CustomHeader != "" {
		headerValue := c.GetHeader(config.CustomHeader)
		if config.CustomHeaderValue != "" {
			return headerValue == config.CustomHeaderValue
		}
		return headerValue != ""
	}

	// CHECK 2: Origin header validation
	origin := c.GetHeader("Origin")
	if len(config.AllowedOrigins) > 0 {
		for _, allowedOrigin := range config.AllowedOrigins {
			if origin == allowedOrigin {
				return true
			}
		}
		// Jika RequireOrigin=true dan origin tidak match, return false
		if config.RequireOrigin {
			return false
		}
	}

	// CHECK 3: Referer header validation
	if len(config.AllowedReferers) > 0 {
		referer := c.GetHeader("Referer")
		for _, allowedReferer := range config.AllowedReferers {
			if strings.Contains(referer, allowedReferer) {
				return true
			}
		}
	}

	// CHECK 4: Browser User-Agent check (jika diaktifkan)
	if config.BypassForBrowsers {
		userAgent := c.GetHeader("User-Agent")
		browserUserAgents := []string{"Mozilla", "Chrome", "Safari", "Firefox", "Edge"}
		for _, ua := range browserUserAgents {
			if strings.Contains(userAgent, ua) {
				return true
			}
		}
	}

	return false
}
