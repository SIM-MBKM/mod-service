package helpers

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// SecurityAccessKey implementasi yang kompatibel dengan Laravel Security
type SecurityAccessKey struct{}

// GetKey mendapatkan APP_KEY dari environment
func (w *SecurityAccessKey) GetKey() string {
	key := os.Getenv("APP_KEY")
	if key == "" {
		key = "v9N+xLCNqMhbBWv1YNFLDpFDR9S1e62gHHfdIwYQHYs="
	}
	return key
}

// GetHash mendapatkan hash method
func (w *SecurityAccessKey) GetHash() string {
	hash := os.Getenv("APP_HASH")
	if hash == "" {
		hash = "sha256"
	}
	return hash
}

// GetCipher mendapatkan cipher
func (w *SecurityAccessKey) GetCipher() string {
	cipher := os.Getenv("APP_CIPHER")
	if cipher == "" {
		cipher = "aes-256-cbc"
	}
	return cipher
}

// GenerateAccessKey membuat Access-Key yang kompatibel dengan Laravel
func (w *SecurityAccessKey) GenerateAccessKey() (string, error) {
	// Format nilai: key@timestamp
	timestamp := time.Now().Unix()
	value := fmt.Sprintf("%s@%d", w.GetKey(), timestamp)

	// Encrypt nilai
	return w.Encrypt(value)
}

// Encrypt mengenkripsi nilai persis seperti Laravel
func (w *SecurityAccessKey) Encrypt(value string) (string, error) {
	// 1. Generate key dengan hash (sama seperti Laravel)
	keyHex := w.hashKey()

	// 2. Generate IV (sama seperti Laravel)
	// PENTING: Laravel menggunakan 16 karakter pertama dari key hex sebagai IV
	ivHex := keyHex[:16]

	// 3. Serialize nilai (sama seperti Laravel)
	serialized := w.phpSerialize(value)

	// 4. Encrypt dengan AES-CBC
	// PENTING: Gunakan ASCII bytes dari hex string seperti yang dilakukan PHP!
	// Ambil 32 byte pertama dari ASCII string hex untuk key
	keyBytes := []byte(keyHex)[:32]

	// Gunakan semua 16 byte ASCII dari string hex untuk IV
	ivBytes := []byte(ivHex)

	// 4.1 Buat block cipher
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// 4.2 Pad data dengan PKCS#7
	paddedData := w.pkcs7Pad([]byte(serialized), aes.BlockSize)

	// 4.3 Encrypt dengan CBC mode
	encryptedData := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, ivBytes)
	mode.CryptBlocks(encryptedData, paddedData)

	// 4.4 Base64 encode hasil enkripsi (sama seperti Laravel)
	encryptedStr := base64.StdEncoding.EncodeToString(encryptedData)

	// 5. Base64 encode sekali lagi (sama seperti Laravel)
	encodedValue := base64.StdEncoding.EncodeToString([]byte(encryptedStr))

	return encodedValue, nil
}

// Decrypt mendekripsi nilai persis seperti Laravel
func (w *SecurityAccessKey) Decrypt(value string) (string, error) {
	// 1. Generate key dengan hash
	keyHex := w.hashKey()

	// 2. Generate IV
	ivHex := keyHex[:16]

	// 3. Base64 decode (sama seperti Laravel)
	decodedValue, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 (outer): %v", err)
	}

	// 3.1 Decode lagi (Laravel melakukan base64 encode dua kali)
	decodedStr := string(decodedValue)
	ciphertext, err := base64.StdEncoding.DecodeString(decodedStr)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 (inner): %v", err)
	}

	// 4. Decrypt dengan AES-CBC
	// PENTING: Gunakan ASCII bytes dari hex string seperti yang dilakukan PHP!
	// Ambil 32 byte pertama dari ASCII string hex untuk key
	keyBytes := []byte(keyHex)[:32]

	// Gunakan semua 16 byte ASCII dari string hex untuk IV
	ivBytes := []byte(ivHex)

	// 4.1 Buat block cipher
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create cipher: %v", err)
	}

	// 4.2 Decrypt
	if len(ciphertext)%aes.BlockSize != 0 {
		return "", fmt.Errorf("ciphertext is not a multiple of block size")
	}

	decrypted := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, ivBytes)
	mode.CryptBlocks(decrypted, ciphertext)

	// 4.3 Unpad dengan PKCS#7
	unpaddedData, err := w.pkcs7Unpad(decrypted)
	if err != nil {
		log.Printf("Warning: unpadding error: %v, attempting to continue", err)
		// Try to continue even with padding error
		unpaddedData = decrypted
	}

	decryptedStr := string(unpaddedData)

	// 5. Unserialize
	if !strings.HasPrefix(decryptedStr, "s:") {
		return decryptedStr, nil
	}

	unserializedValue, err := w.phpUnserialize(decryptedStr)
	if err != nil {
		log.Printf("Warning: unserialize error: %v, returning raw value", err)
		return decryptedStr, nil
	}

	return unserializedValue, nil
}

// hashKey menghasilkan hash key persis seperti Laravel
func (w *SecurityAccessKey) hashKey() string {
	// PHP: hash('sha256', config('srcservice.key'))
	hasher := sha256.New()
	hasher.Write([]byte(w.GetKey()))
	return hex.EncodeToString(hasher.Sum(nil))
}

// phpSerialize mengimplementasikan PHP serialize() untuk string
func (w *SecurityAccessKey) phpSerialize(value string) string {
	// Format: s:length:"content";
	return fmt.Sprintf("s:%d:\"%s\";", len(value), value)
}

// phpUnserialize mengimplementasikan PHP unserialize() untuk string
func (w *SecurityAccessKey) phpUnserialize(value string) (string, error) {
	// Expected format: s:length:"content";
	if !strings.HasPrefix(value, "s:") {
		return "", fmt.Errorf("not a serialized string")
	}

	parts := strings.SplitN(value, ":", 3)
	if len(parts) < 3 {
		return "", fmt.Errorf("invalid format")
	}

	// Get length
	lengthStr := parts[1]
	length, err := strconv.Atoi(lengthStr)
	if err != nil {
		return "", fmt.Errorf("invalid length")
	}

	// Extract content
	contentParts := strings.SplitN(parts[2], ";", 2)
	if len(contentParts) < 1 {
		return "", fmt.Errorf("invalid content format")
	}

	content := contentParts[0]
	if strings.HasPrefix(content, "\"") && strings.HasSuffix(content, "\"") {
		content = content[1 : len(content)-1]
	}

	// Verify length
	if len(content) != length {
		return "", fmt.Errorf("content length mismatch, expected %d, got %d", length, len(content))
	}

	return content, nil
}

// pkcs7Pad pads data according to PKCS#7
func (w *SecurityAccessKey) pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - (len(data) % blockSize)
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}

// pkcs7Unpad removes PKCS#7 padding
func (w *SecurityAccessKey) pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, fmt.Errorf("empty data")
	}

	padding := int(data[length-1])
	if padding > length || padding == 0 {
		return nil, fmt.Errorf("invalid padding size")
	}

	for i := length - padding; i < length; i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return data[:length-padding], nil
}

// NewSecurityAccessKey creates a new instance
func NewSecurityAccessKey() *SecurityAccessKey {
	return &SecurityAccessKey{}
}
