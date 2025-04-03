package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

// Errors
var (
	ErrEncryptionFailed  = errors.New("encryption failed")
	ErrDecryptionFailed  = errors.New("decryption failed")
	ErrInvalidKey        = errors.New("invalid encryption key")
	ErrInvalidInput      = errors.New("invalid input data")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

// EncryptionService provides methods for encrypting and decrypting data
type EncryptionService struct {
	key    []byte
	salt   []byte
	aesGCM cipher.AEAD
}

// NewEncryptionService creates a new encryption service
func NewEncryptionService(key, salt string) (*EncryptionService, error) {
	if key == "" || salt == "" {
		return nil, ErrInvalidKey
	}

	// Derive a secure key using PBKDF2
	derivedKey := pbkdf2.Key([]byte(key), []byte(salt), 10000, 32, sha256.New)

	// Create the AES-GCM cipher
	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Create the GCM mode with the standard nonce size
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	return &EncryptionService{
		key:    derivedKey,
		salt:   []byte(salt),
		aesGCM: aesGCM,
	}, nil
}

// Encrypt encrypts data using AES-GCM
func (s *EncryptionService) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		return "", ErrInvalidInput
	}

	// Create a nonce
	nonce := make([]byte, s.aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Encrypt the data
	ciphertext := s.aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	// Return as base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts data using AES-GCM
func (s *EncryptionService) Decrypt(encryptedData string) (string, error) {
	if encryptedData == "" {
		return "", ErrInvalidInput
	}

	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidCiphertext, err)
	}

	// Extract the nonce from the ciphertext
	nonceSize := s.aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", ErrInvalidCiphertext
	}

	nonce, encryptedValue := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	plaintext, err := s.aesGCM.Open(nil, nonce, encryptedValue, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return string(plaintext), nil
}

// EncryptField encrypts a specific field for a record
func (s *EncryptionService) EncryptField(recordType, recordID, fieldName, value string) (string, error) {
	// Create a field-specific context for additional security
	context := fmt.Sprintf("%s.%s.%s", recordType, recordID, fieldName)

	// Encrypt the value with the context
	encrypted, err := s.encryptWithContext(value, context)
	if err != nil {
		return "", err
	}

	return encrypted, nil
}

// DecryptField decrypts a specific field for a record
func (s *EncryptionService) DecryptField(recordType, recordID, fieldName, encryptedValue string) (string, error) {
	// Recreate the same context used for encryption
	context := fmt.Sprintf("%s.%s.%s", recordType, recordID, fieldName)

	// Decrypt the value with the context
	decrypted, err := s.decryptWithContext(encryptedValue, context)
	if err != nil {
		return "", err
	}

	return decrypted, nil
}

// encryptWithContext encrypts data with an additional context for authenticated encryption
func (s *EncryptionService) encryptWithContext(plaintext, context string) (string, error) {
	if plaintext == "" {
		return "", ErrInvalidInput
	}

	// Create a nonce
	nonce := make([]byte, s.aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Encrypt the data with the context as additional authenticated data
	ciphertext := s.aesGCM.Seal(nonce, nonce, []byte(plaintext), []byte(context))

	// Return as base64
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decryptWithContext decrypts data with an additional context for authenticated encryption
func (s *EncryptionService) decryptWithContext(encryptedData, context string) (string, error) {
	if encryptedData == "" {
		return "", ErrInvalidInput
	}

	// Decode base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidCiphertext, err)
	}

	// Extract the nonce from the ciphertext
	nonceSize := s.aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", ErrInvalidCiphertext
	}

	nonce, encryptedValue := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data with the context as additional authenticated data
	plaintext, err := s.aesGCM.Open(nil, nonce, encryptedValue, []byte(context))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return string(plaintext), nil
}

// RotateKey rotates the encryption key
func (s *EncryptionService) RotateKey(newKey, newSalt string) error {
	if newKey == "" || newSalt == "" {
		return ErrInvalidKey
	}

	// Derive a new secure key using PBKDF2
	newDerivedKey := pbkdf2.Key([]byte(newKey), []byte(newSalt), 10000, 32, sha256.New)

	// Create the new AES-GCM cipher
	block, err := aes.NewCipher(newDerivedKey)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Create the GCM mode with the standard nonce size
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrEncryptionFailed, err)
	}

	// Update the service with the new key and cipher
	s.key = newDerivedKey
	s.salt = []byte(newSalt)
	s.aesGCM = aesGCM

	return nil
}

// HashPassword creates a one-way hash for passwords
func (s *EncryptionService) HashPassword(password string) (string, error) {
	if password == "" {
		return "", ErrInvalidInput
	}

	// Use PBKDF2 for password hashing with a random salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}

	// Derive the key
	hash := pbkdf2.Key([]byte(password), salt, 15000, 32, sha256.New)

	// Combine salt and hash for storage
	result := make([]byte, len(salt)+len(hash))
	copy(result, salt)
	copy(result[len(salt):], hash)

	return base64.StdEncoding.EncodeToString(result), nil
}

// VerifyPassword verifies a password against its hash
func (s *EncryptionService) VerifyPassword(password, storedHash string) (bool, error) {
	if password == "" || storedHash == "" {
		return false, ErrInvalidInput
	}

	// Decode the stored hash
	decoded, err := base64.StdEncoding.DecodeString(storedHash)
	if err != nil {
		return false, fmt.Errorf("invalid hash format: %v", err)
	}

	// Extract salt and hash
	if len(decoded) < 17 { // salt(16) + at least 1 byte hash
		return false, errors.New("invalid hash length")
	}
	salt, storedKey := decoded[:16], decoded[16:]

	// Compute the hash with the same salt
	computedKey := pbkdf2.Key([]byte(password), salt, 15000, 32, sha256.New)

	// Compare the computed hash with the stored hash
	return compareHashes(storedKey, computedKey), nil
}

// compareHashes compares two hashes in constant time to prevent timing attacks
func compareHashes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}

	return result == 0
}
