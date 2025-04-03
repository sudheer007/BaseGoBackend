package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// List of encryption algorithms supported
type CryptoAlgorithm string

const (
	// AlgorithmAESGCM uses AES-256 in GCM mode with a 96-bit nonce
	AlgorithmAESGCM CryptoAlgorithm = "AES-GCM"

	// AlgorithmChaCha20Poly1305 uses ChaCha20-Poly1305 AEAD
	AlgorithmChaCha20Poly1305 CryptoAlgorithm = "ChaCha20-Poly1305"
)

// Common cryptographic errors
var (
	// ErrCryptoEncryptionFailed is returned when data encryption fails
	ErrCryptoEncryptionFailed = errors.New("encryption failed")

	// ErrCryptoDecryptionFailed is returned when data decryption fails
	ErrCryptoDecryptionFailed = errors.New("decryption failed")

	// ErrCryptoInvalidKey is returned when the key is invalid or wrong format
	ErrCryptoInvalidKey = errors.New("invalid encryption key")

	// ErrInvalidKeyVersion is returned when the key version does not exist
	ErrInvalidKeyVersion = errors.New("invalid key version")

	// ErrDataCorrupted is returned when encrypted data is corrupted
	ErrDataCorrupted = errors.New("encrypted data corrupted")

	// ErrInvalidAlgorithm is returned when an unsupported algorithm is specified
	ErrInvalidAlgorithm = errors.New("invalid encryption algorithm")

	// ErrAuthenticationFailed is returned when HMAC verification fails
	ErrAuthenticationFailed = errors.New("authentication failed")
)

// EncryptionKey holds a key used for encryption/decryption operations
type EncryptionKey struct {
	// ID is the unique identifier for this key
	ID string

	// Version is the key version number (used for rotation)
	Version int

	// Algorithm defines which encryption algorithm to use
	Algorithm CryptoAlgorithm

	// Key is the raw key material
	Key []byte

	// Created is when this key was created
	Created time.Time

	// LastUsed is when this key was last used
	LastUsed time.Time

	// IsActive indicates if this key is active for encryption
	IsActive bool
}

// EncryptionMetadata holds metadata about an encrypted piece of data
type EncryptionMetadata struct {
	// KeyID identifies which key was used for encryption
	KeyID string

	// KeyVersion indicates which version of the key was used
	KeyVersion int

	// Algorithm is the encryption algorithm used
	Algorithm CryptoAlgorithm

	// Timestamp is when the data was encrypted
	Timestamp time.Time

	// Nonce is the initialization vector or nonce
	Nonce []byte

	// AdditionalData is any additional authenticated data
	AdditionalData []byte
}

// EncryptedData represents data that has been encrypted
type EncryptedData struct {
	// Metadata about the encryption
	Metadata EncryptionMetadata

	// Ciphertext is the encrypted data
	Ciphertext []byte
}

// CryptoService provides cryptographic operations
type CryptoService struct {
	// Keys by ID and version
	keys map[string]map[int]*EncryptionKey

	// Current key ID used for encryption
	currentKeyID string

	// Lock for concurrent access
	mutex sync.RWMutex
}

// CryptoConfig defines configuration for the crypto service
type CryptoConfig struct {
	// Default algorithm to use for encryption
	DefaultAlgorithm CryptoAlgorithm
}

// DefaultCryptoConfig returns the default crypto configuration
func DefaultCryptoConfig() *CryptoConfig {
	return &CryptoConfig{
		DefaultAlgorithm: AlgorithmAESGCM,
	}
}

// NewCryptoService creates a new crypto service
func NewCryptoService() *CryptoService {
	return &CryptoService{
		keys: make(map[string]map[int]*EncryptionKey),
	}
}

// AddKey adds a new encryption key to the service
func (cs *CryptoService) AddKey(key *EncryptionKey) error {
	if key == nil {
		return ErrCryptoInvalidKey
	}

	if len(key.Key) == 0 {
		return ErrCryptoInvalidKey
	}

	if key.ID == "" {
		key.ID = uuid.New().String()
	}

	// Validate algorithm
	switch key.Algorithm {
	case AlgorithmAESGCM:
		// AES-256 requires a 32-byte key
		if len(key.Key) != 32 {
			return fmt.Errorf("%w: AES-256-GCM requires a 32-byte key", ErrCryptoInvalidKey)
		}
	case AlgorithmChaCha20Poly1305:
		// ChaCha20-Poly1305 requires a 32-byte key
		if len(key.Key) != chacha20poly1305.KeySize {
			return fmt.Errorf("%w: ChaCha20-Poly1305 requires a %d-byte key", ErrCryptoInvalidKey, chacha20poly1305.KeySize)
		}
	default:
		return fmt.Errorf("%w: %s", ErrInvalidAlgorithm, key.Algorithm)
	}

	// Set timestamps if not already set
	if key.Created.IsZero() {
		key.Created = time.Now()
	}

	cs.mutex.Lock()
	defer cs.mutex.Unlock()

	// Check if this key ID exists, if not create the map
	if _, exists := cs.keys[key.ID]; !exists {
		cs.keys[key.ID] = make(map[int]*EncryptionKey)
	}

	// Add the key
	cs.keys[key.ID][key.Version] = key

	// If this is an active key, set it as the current key
	if key.IsActive {
		cs.currentKeyID = key.ID
	}

	return nil
}

// GetKey retrieves an encryption key by ID and version
func (cs *CryptoService) GetKey(keyID string, version int) (*EncryptionKey, error) {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()

	// Check if key ID exists
	versions, exists := cs.keys[keyID]
	if !exists {
		return nil, ErrCryptoInvalidKey
	}

	// Check if version exists
	key, exists := versions[version]
	if !exists {
		return nil, ErrInvalidKeyVersion
	}

	// Update last used time
	key.LastUsed = time.Now()

	return key, nil
}

// GetCurrentKey gets the currently active key for encryption
func (cs *CryptoService) GetCurrentKey() (*EncryptionKey, error) {
	cs.mutex.RLock()
	defer cs.mutex.RUnlock()

	if cs.currentKeyID == "" {
		return nil, errors.New("no active encryption key available")
	}

	// Find the active key with the highest version
	versions := cs.keys[cs.currentKeyID]
	var highestVersion int
	var currentKey *EncryptionKey

	for version, key := range versions {
		if key.IsActive && version > highestVersion {
			highestVersion = version
			currentKey = key
		}
	}

	if currentKey == nil {
		return nil, errors.New("no active encryption key version found")
	}

	// Update last used time
	currentKey.LastUsed = time.Now()

	return currentKey, nil
}

// GenerateRandomKey generates a cryptographically secure random key
func (cs *CryptoService) GenerateRandomKey(algorithm CryptoAlgorithm) ([]byte, error) {
	var keySize int

	switch algorithm {
	case AlgorithmAESGCM:
		keySize = 32 // 256 bits
	case AlgorithmChaCha20Poly1305:
		keySize = chacha20poly1305.KeySize
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidAlgorithm, algorithm)
	}

	key := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	return key, nil
}

// GenerateKeyFromPassword derives a key from a password using Argon2id
func (cs *CryptoService) GenerateKeyFromPassword(password, salt []byte, algorithm CryptoAlgorithm) ([]byte, error) {
	var keySize int

	switch algorithm {
	case AlgorithmAESGCM:
		keySize = 32 // 256 bits
	case AlgorithmChaCha20Poly1305:
		keySize = chacha20poly1305.KeySize
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidAlgorithm, algorithm)
	}

	// Generate a salt if not provided
	if len(salt) == 0 {
		salt = make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, fmt.Errorf("failed to generate salt: %w", err)
		}
	}

	// Use Argon2id for key derivation
	// Time: 1, Memory: 64MB, Threads: 4, Key Length: keySize
	return argon2.IDKey(password, salt, 1, 64*1024, 4, uint32(keySize)), nil
}

// CreateKey creates a new encryption key and adds it to the service
func (cs *CryptoService) CreateKey(algorithm CryptoAlgorithm, isActive bool) (*EncryptionKey, error) {
	// Generate a random key
	keyBytes, err := cs.GenerateRandomKey(algorithm)
	if err != nil {
		return nil, err
	}

	// Find the next version number for a new key
	var version int = 1

	if isActive {
		cs.mutex.RLock()

		// If we're creating an active key and there's an existing active key,
		// increment its version
		if cs.currentKeyID != "" {
			for v := range cs.keys[cs.currentKeyID] {
				if v >= version {
					version = v + 1
				}
			}
		}

		cs.mutex.RUnlock()
	}

	// Create the key
	key := &EncryptionKey{
		ID:        uuid.New().String(),
		Version:   version,
		Algorithm: algorithm,
		Key:       keyBytes,
		Created:   time.Now(),
		LastUsed:  time.Now(),
		IsActive:  isActive,
	}

	// Add it to the service
	if err := cs.AddKey(key); err != nil {
		return nil, err
	}

	return key, nil
}

// RotateKey creates a new version of the current key
func (cs *CryptoService) RotateKey() (*EncryptionKey, error) {
	currentKey, err := cs.GetCurrentKey()
	if err != nil {
		return nil, err
	}

	// Generate a new random key with the same algorithm
	keyBytes, err := cs.GenerateRandomKey(currentKey.Algorithm)
	if err != nil {
		return nil, err
	}

	// Create a new version of the key
	newKey := &EncryptionKey{
		ID:        currentKey.ID,
		Version:   currentKey.Version + 1,
		Algorithm: currentKey.Algorithm,
		Key:       keyBytes,
		Created:   time.Now(),
		LastUsed:  time.Now(),
		IsActive:  true,
	}

	// Mark the current key as inactive
	cs.mutex.Lock()
	currentKey.IsActive = false
	cs.mutex.Unlock()

	// Add the new key
	if err := cs.AddKey(newKey); err != nil {
		return nil, err
	}

	return newKey, nil
}

// Encrypt encrypts data using the current active key
func (cs *CryptoService) Encrypt(plaintext, additionalData []byte) (*EncryptedData, error) {
	key, err := cs.GetCurrentKey()
	if err != nil {
		return nil, err
	}

	return cs.EncryptWithKey(plaintext, additionalData, key)
}

// EncryptWithKey encrypts data using a specific key
func (cs *CryptoService) EncryptWithKey(plaintext, additionalData []byte, key *EncryptionKey) (*EncryptedData, error) {
	if key == nil {
		return nil, ErrCryptoInvalidKey
	}

	// Create metadata
	metadata := EncryptionMetadata{
		KeyID:          key.ID,
		KeyVersion:     key.Version,
		Algorithm:      key.Algorithm,
		Timestamp:      time.Now(),
		AdditionalData: additionalData,
	}

	var ciphertext []byte
	var err error

	switch key.Algorithm {
	case AlgorithmAESGCM:
		ciphertext, metadata.Nonce, err = encryptAESGCM(plaintext, additionalData, key.Key)
	case AlgorithmChaCha20Poly1305:
		ciphertext, metadata.Nonce, err = encryptChaCha20Poly1305(plaintext, additionalData, key.Key)
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidAlgorithm, key.Algorithm)
	}

	if err != nil {
		return nil, err
	}

	return &EncryptedData{
		Metadata:   metadata,
		Ciphertext: ciphertext,
	}, nil
}

// Decrypt decrypts data
func (cs *CryptoService) Decrypt(data *EncryptedData) ([]byte, error) {
	if data == nil {
		return nil, ErrDataCorrupted
	}

	// Get the key used for encryption
	key, err := cs.GetKey(data.Metadata.KeyID, data.Metadata.KeyVersion)
	if err != nil {
		return nil, err
	}

	var plaintext []byte

	switch data.Metadata.Algorithm {
	case AlgorithmAESGCM:
		plaintext, err = decryptAESGCM(data.Ciphertext, data.Metadata.AdditionalData, data.Metadata.Nonce, key.Key)
	case AlgorithmChaCha20Poly1305:
		plaintext, err = decryptChaCha20Poly1305(data.Ciphertext, data.Metadata.AdditionalData, data.Metadata.Nonce, key.Key)
	default:
		return nil, fmt.Errorf("%w: %s", ErrInvalidAlgorithm, data.Metadata.Algorithm)
	}

	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// SerializeEncryptedData serializes encrypted data to a byte array
func (cs *CryptoService) SerializeEncryptedData(data *EncryptedData) ([]byte, error) {
	if data == nil {
		return nil, errors.New("encrypted data is nil")
	}

	// Format:
	// - 1 byte: version (currently 1)
	// - 16 bytes: UUID of the key
	// - 4 bytes: key version (uint32)
	// - 16 bytes: algorithm name (padded with zeros)
	// - 8 bytes: timestamp (int64, Unix timestamp in nanoseconds)
	// - 2 bytes: nonce length (uint16)
	// - N bytes: nonce
	// - 2 bytes: additional data length (uint16)
	// - M bytes: additional data
	// - 4 bytes: ciphertext length (uint32)
	// - P bytes: ciphertext
	// - 32 bytes: HMAC-SHA256 of all preceding bytes

	// Convert UUID to bytes
	keyID, err := uuid.Parse(data.Metadata.KeyID)
	if err != nil {
		return nil, fmt.Errorf("invalid key ID: %w", err)
	}

	// Prepare buffer
	buf := bytes.NewBuffer(nil)

	// Version
	buf.WriteByte(1)

	// Key UUID
	buf.Write(keyID[:])

	// Key version
	binary.Write(buf, binary.BigEndian, uint32(data.Metadata.KeyVersion))

	// Algorithm (padded to 16 bytes)
	algBytes := make([]byte, 16)
	copy(algBytes, []byte(data.Metadata.Algorithm))
	buf.Write(algBytes)

	// Timestamp
	binary.Write(buf, binary.BigEndian, data.Metadata.Timestamp.UnixNano())

	// Nonce
	binary.Write(buf, binary.BigEndian, uint16(len(data.Metadata.Nonce)))
	buf.Write(data.Metadata.Nonce)

	// Additional data
	binary.Write(buf, binary.BigEndian, uint16(len(data.Metadata.AdditionalData)))
	buf.Write(data.Metadata.AdditionalData)

	// Ciphertext
	binary.Write(buf, binary.BigEndian, uint32(len(data.Ciphertext)))
	buf.Write(data.Ciphertext)

	// Get the data without HMAC
	dataWithoutHMAC := buf.Bytes()

	// Calculate HMAC
	key, err := cs.GetKey(data.Metadata.KeyID, data.Metadata.KeyVersion)
	if err != nil {
		return nil, err
	}

	// Derive an HMAC key from the encryption key
	hmacKey := deriveHMACKey(key.Key)

	h := hmac.New(sha256.New, hmacKey)
	h.Write(dataWithoutHMAC)
	mac := h.Sum(nil)

	// Append HMAC
	buf.Write(mac)

	return buf.Bytes(), nil
}

// DeserializeEncryptedData deserializes a byte array to encrypted data
func (cs *CryptoService) DeserializeEncryptedData(data []byte) (*EncryptedData, error) {
	if len(data) < 85 { // 1 + 16 + 4 + 16 + 8 + 2 + 2 + 4 + 32 = 85 (minimum size with empty nonce, aad, and ciphertext)
		return nil, errors.New("encrypted data too short")
	}

	// Extract HMAC (last 32 bytes)
	receivedMAC := data[len(data)-32:]
	dataWithoutHMAC := data[:len(data)-32]

	// Create a reader for the data
	buf := bytes.NewReader(dataWithoutHMAC)

	// Version
	version, err := buf.ReadByte()
	if err != nil {
		return nil, err
	}

	if version != 1 {
		return nil, fmt.Errorf("unsupported version: %d", version)
	}

	// Key UUID
	keyUUID := make([]byte, 16)
	if _, err := io.ReadFull(buf, keyUUID); err != nil {
		return nil, err
	}
	keyID := uuid.UUID(keyUUID)

	// Key version
	var keyVersion uint32
	if err := binary.Read(buf, binary.BigEndian, &keyVersion); err != nil {
		return nil, err
	}

	// Algorithm
	algBytes := make([]byte, 16)
	if _, err := io.ReadFull(buf, algBytes); err != nil {
		return nil, err
	}
	// Trim null bytes
	algorithmStr := string(bytes.TrimRight(algBytes, "\x00"))
	algorithm := CryptoAlgorithm(algorithmStr)

	// Timestamp
	var timestamp int64
	if err := binary.Read(buf, binary.BigEndian, &timestamp); err != nil {
		return nil, err
	}

	// Nonce
	var nonceLen uint16
	if err := binary.Read(buf, binary.BigEndian, &nonceLen); err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := io.ReadFull(buf, nonce); err != nil {
		return nil, err
	}

	// Additional data
	var aadLen uint16
	if err := binary.Read(buf, binary.BigEndian, &aadLen); err != nil {
		return nil, err
	}
	aad := make([]byte, aadLen)
	if _, err := io.ReadFull(buf, aad); err != nil {
		return nil, err
	}

	// Ciphertext
	var ciphertextLen uint32
	if err := binary.Read(buf, binary.BigEndian, &ciphertextLen); err != nil {
		return nil, err
	}
	ciphertext := make([]byte, ciphertextLen)
	if _, err := io.ReadFull(buf, ciphertext); err != nil {
		return nil, err
	}

	// Get the key for HMAC verification
	key, err := cs.GetKey(keyID.String(), int(keyVersion))
	if err != nil {
		return nil, err
	}

	// Derive HMAC key
	hmacKey := deriveHMACKey(key.Key)

	// Verify HMAC
	h := hmac.New(sha256.New, hmacKey)
	h.Write(dataWithoutHMAC)
	expectedMAC := h.Sum(nil)

	if subtle.ConstantTimeCompare(receivedMAC, expectedMAC) != 1 {
		return nil, ErrAuthenticationFailed
	}

	// Create and return the EncryptedData
	return &EncryptedData{
		Metadata: EncryptionMetadata{
			KeyID:          keyID.String(),
			KeyVersion:     int(keyVersion),
			Algorithm:      algorithm,
			Timestamp:      time.Unix(0, timestamp),
			Nonce:          nonce,
			AdditionalData: aad,
		},
		Ciphertext: ciphertext,
	}, nil
}

// EncryptToString encrypts data and returns a base64-encoded string
func (cs *CryptoService) EncryptToString(plaintext, additionalData []byte) (string, error) {
	encData, err := cs.Encrypt(plaintext, additionalData)
	if err != nil {
		return "", err
	}

	serialized, err := cs.SerializeEncryptedData(encData)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(serialized), nil
}

// DecryptFromString decrypts a base64-encoded string
func (cs *CryptoService) DecryptFromString(encodedData string) ([]byte, error) {
	serialized, err := base64.URLEncoding.DecodeString(encodedData)
	if err != nil {
		return nil, fmt.Errorf("invalid base64: %w", err)
	}

	encData, err := cs.DeserializeEncryptedData(serialized)
	if err != nil {
		return nil, err
	}

	return cs.Decrypt(encData)
}

// ComputeHMAC computes an HMAC for the given data using the specified key
func (cs *CryptoService) ComputeHMAC(data []byte, keyID string, keyVersion int) ([]byte, error) {
	key, err := cs.GetKey(keyID, keyVersion)
	if err != nil {
		return nil, err
	}

	// Derive an HMAC key from the encryption key
	hmacKey := deriveHMACKey(key.Key)

	h := hmac.New(sha256.New, hmacKey)
	h.Write(data)
	return h.Sum(nil), nil
}

// VerifyHMAC verifies an HMAC for the given data
func (cs *CryptoService) VerifyHMAC(data, mac []byte, keyID string, keyVersion int) (bool, error) {
	expectedMAC, err := cs.ComputeHMAC(data, keyID, keyVersion)
	if err != nil {
		return false, err
	}

	return subtle.ConstantTimeCompare(mac, expectedMAC) == 1, nil
}

// HashPassword securely hashes a password using Argon2id
func (cs *CryptoService) HashPassword(password []byte) (string, error) {
	// Generate a random salt
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Configure Argon2id parameters
	// Time: 3, Memory: 64MB, Threads: 2, Key Length: 32
	time := uint32(3)
	memory := uint32(64 * 1024)
	threads := uint8(2)
	keyLen := uint32(32)

	// Generate the hash
	hash := argon2.IDKey(password, salt, time, memory, threads, keyLen)

	// Format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encodedHash := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		memory, time, threads, b64Salt, b64Hash)

	return encodedHash, nil
}

// VerifyPassword verifies a password against a hash
func (cs *CryptoService) VerifyPassword(password []byte, encodedHash string) (bool, error) {
	// Extract parameters, salt and hash from the encoded hash
	parts := bytes.Split([]byte(encodedHash), []byte("$"))
	if len(parts) != 6 {
		return false, errors.New("invalid hash format")
	}

	if string(parts[1]) != "argon2id" {
		return false, errors.New("unsupported algorithm")
	}

	var version int
	_, err := fmt.Sscanf(string(parts[2]), "v=%d", &version)
	if err != nil {
		return false, err
	}
	if version != 19 {
		return false, errors.New("unsupported version")
	}

	// Parse parameters
	var memory, time uint32
	var threads uint8
	_, err = fmt.Sscanf(string(parts[3]), "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil {
		return false, err
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(string(parts[4]))
	if err != nil {
		return false, err
	}

	decodedHash, err := base64.RawStdEncoding.DecodeString(string(parts[5]))
	if err != nil {
		return false, err
	}

	// Compute hash with the same parameters
	keyLen := uint32(len(decodedHash))
	computedHash := argon2.IDKey(password, salt, time, memory, threads, keyLen)

	// Compare hashes
	return subtle.ConstantTimeCompare(computedHash, decodedHash) == 1, nil
}

// DeriveKey derives multiple keys from a master key
func (cs *CryptoService) DeriveKey(masterKey []byte, context, salt []byte, keyLen int) ([]byte, error) {
	// Use HKDF to derive a key
	hkdf := hkdf.New(sha256.New, masterKey, salt, context)

	derivedKey := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdf, derivedKey); err != nil {
		return nil, err
	}

	return derivedKey, nil
}

// GenerateRandomBytes generates random bytes
func (cs *CryptoService) GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, err
	}
	return bytes, nil
}

// Internal helper functions

// encryptAESGCM encrypts data using AES-256 in GCM mode
func encryptAESGCM(plaintext, additionalData, key []byte) (ciphertext, nonce []byte, err error) {
	// Create the cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}

	// Generate a nonce
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// Encrypt and authenticate the plaintext
	ciphertext = gcm.Seal(nil, nonce, plaintext, additionalData)

	return ciphertext, nonce, nil
}

// decryptAESGCM decrypts data using AES-256 in GCM mode
func decryptAESGCM(ciphertext, additionalData, nonce, key []byte) (plaintext []byte, err error) {
	// Create the cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Decrypt and verify the ciphertext
	plaintext, err = gcm.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrCryptoDecryptionFailed
	}

	return plaintext, nil
}

// encryptChaCha20Poly1305 encrypts data using ChaCha20-Poly1305
func encryptChaCha20Poly1305(plaintext, additionalData, key []byte) (ciphertext, nonce []byte, err error) {
	// Create the AEAD cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, nil, err
	}

	// Generate a nonce
	nonce = make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}

	// Encrypt and authenticate the plaintext
	ciphertext = aead.Seal(nil, nonce, plaintext, additionalData)

	return ciphertext, nonce, nil
}

// decryptChaCha20Poly1305 decrypts data using ChaCha20-Poly1305
func decryptChaCha20Poly1305(ciphertext, additionalData, nonce, key []byte) (plaintext []byte, err error) {
	// Create the AEAD cipher
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}

	// Decrypt and verify the ciphertext
	plaintext, err = aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrCryptoDecryptionFailed
	}

	return plaintext, nil
}

// deriveHMACKey derives an HMAC key from an encryption key
func deriveHMACKey(key []byte) []byte {
	// Use HKDF with SHA-512 to derive a separate key for HMAC operations
	info := []byte("HMAC-KEY")
	salt := []byte("hmac-salt")

	reader := hkdf.New(sha512.New, key, salt, info)
	hmacKey := make([]byte, 32) // 256-bit key
	reader.Read(hmacKey)

	return hmacKey
}
