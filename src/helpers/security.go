package helpers

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Security struct
type Security struct {
	hashMethod string
	key        string
	cipherMode string
}

// NewSecurity creates a new instance of Security with configuration
func NewSecurity(hashMethod, key, cipherMode string) *Security {
	return &Security{
		hashMethod: hashMethod,
		key:        key,
		cipherMode: cipherMode,
	}
}

// hash generates a hash based on the hash method
func (s *Security) hash(value string) []byte {
	hash := sha256.Sum256([]byte(value)) // Defaulting to SHA-256
	return hash[:]
}

// Encrypt encrypts the given value
func (s *Security) Encrypt(value interface{}) (string, error) {
	// Serializing value to string (equivalent to PHP serialize)
	serializedValue, err := json.Marshal(value)
	if err != nil {
		return "", err
	}

	// Cek jika key diawali dengan "base64:" dan hapus awalan tersebut
	key := s.key
	if len(key) > 7 && key[:7] == "base64:" {
		key = key[7:]
	}

	// Decode base64 key
	decodedKey, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("error decoding key: %v", err)
	}

	// Pastikan panjang decoded key sesuai untuk AES
	if len(decodedKey) != 32 {
		return "", fmt.Errorf("invalid key length, expected 32 bytes, got %d bytes", len(decodedKey))
	}

	// Generate hash untuk key
	keyHash := s.hash(string(decodedKey))
	// Gunakan bytes pertama AES.BlockSize sebagai IV
	iv := keyHash[:aes.BlockSize]

	block, err := aes.NewCipher(decodedKey)
	if err != nil {
		return "", fmt.Errorf("error creating AES cipher: %v", err)
	}

	// Inisialisasi enkripsi AES CBC
	mode := cipher.NewCBCEncrypter(block, iv)

	// Pastikan panjang data merupakan kelipatan AES.BlockSize
	padding := aes.BlockSize - len(serializedValue)%aes.BlockSize
	paddingData := append(serializedValue, make([]byte, padding)...)

	// Enkripsi data
	encrypted := make([]byte, len(paddingData))
	mode.CryptBlocks(encrypted, paddingData)

	// Encode data terenkripsi menjadi string base64
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// Decrypt decrypts the given encrypted value using AES-256-CBC
func (s *Security) Decrypt(encryptedValue string) (interface{}, error) {
	// Decode the base64 encoded encrypted value
	data, err := base64.StdEncoding.DecodeString(encryptedValue)
	if err != nil {
		return nil, err
	}

	// Decode base64 key
	key, err := base64.StdEncoding.DecodeString(s.key)
	if err != nil {
		return nil, err
	}

	// Generate hash for key
	keyHash := s.hash(string(key))

	// Use first AES.BlockSize bytes as IV
	iv := keyHash[:aes.BlockSize]

	// Initialize AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	// Initialize the AES CBC decrypter
	mode := cipher.NewCBCDecrypter(block, iv)

	// Decrypt the data
	decrypted := make([]byte, len(data))
	mode.CryptBlocks(decrypted, data)

	// Remove padding (check for null characters and remove them if necessary)
	padding := decrypted[len(decrypted)-1]
	decrypted = decrypted[:len(decrypted)-int(padding)]

	// Trim any remaining null characters
	decrypted = []byte(strings.TrimRight(string(decrypted), "\x00"))

	// Unmarshal the decrypted data
	var result interface{}
	err = json.Unmarshal([]byte(decrypted), &result)
	if err != nil {
		return nil, err
	}

	return result, nil
}
