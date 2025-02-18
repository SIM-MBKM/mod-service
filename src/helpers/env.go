package helpers

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

// LoadEnv loads environment variables from a .env file.
func LoadEnv() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found or failed to load. Using system environment variables if available.")
	}
}

// GetEnv retrieves the value of an environment variable or returns a fallback if not set.
func GetEnv(key string, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return fallback
}

func Config(key string) string {

	return os.Getenv(key)

}
