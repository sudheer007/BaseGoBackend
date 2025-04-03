package security

import (
	"testing"
)

func TestEncryptionService(t *testing.T) {
	// Initialize the encryption service
	key := "test-encryption-key-for-unit-tests-only"
	salt := "test-salt-for-unit-tests-only"

	svc, err := NewEncryptionService(key, salt)
	if err != nil {
		t.Fatalf("Failed to initialize encryption service: %v", err)
	}

	// Test basic encryption and decryption
	originalText := "sensitive data that should be encrypted"

	// Encrypt
	encrypted, err := svc.Encrypt(originalText)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify encrypted text is different from original
	if encrypted == originalText {
		t.Errorf("Encrypted text should be different from original")
	}

	// Decrypt
	decrypted, err := svc.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// Verify decryption works correctly
	if decrypted != originalText {
		t.Errorf("Expected decrypted text to be '%s', but got '%s'", originalText, decrypted)
	}

	// Test field-level encryption with context
	recordType := "User"
	recordID := "user-123"
	fieldName := "SSN"
	fieldValue := "123-45-6789"

	// Encrypt the field
	encryptedField, err := svc.EncryptField(recordType, recordID, fieldName, fieldValue)
	if err != nil {
		t.Fatalf("Field encryption failed: %v", err)
	}

	// Decrypt the field
	decryptedField, err := svc.DecryptField(recordType, recordID, fieldName, encryptedField)
	if err != nil {
		t.Fatalf("Field decryption failed: %v", err)
	}

	// Verify field encryption works correctly
	if decryptedField != fieldValue {
		t.Errorf("Expected decrypted field to be '%s', but got '%s'", fieldValue, decryptedField)
	}

	// Test decryption with wrong context fails
	wrongContext := "wrong-context"
	_, err = svc.DecryptField(wrongContext, recordID, fieldName, encryptedField)
	if err == nil {
		t.Errorf("Decryption with wrong context should fail")
	}

	// Test password hashing and verification
	password := "secure-password-123!"

	// Hash the password
	hashedPassword, err := svc.HashPassword(password)
	if err != nil {
		t.Fatalf("Password hashing failed: %v", err)
	}

	// Verify correct password
	valid, err := svc.VerifyPassword(password, hashedPassword)
	if err != nil {
		t.Fatalf("Password verification failed: %v", err)
	}
	if !valid {
		t.Errorf("Password verification failed: should be valid")
	}

	// Verify incorrect password
	wrongPassword := "wrong-password"
	valid, err = svc.VerifyPassword(wrongPassword, hashedPassword)
	if err != nil {
		t.Fatalf("Password verification failed: %v", err)
	}
	if valid {
		t.Errorf("Password verification failed: should be invalid")
	}

	// Test key rotation
	newKey := "new-test-encryption-key-for-rotation"
	newSalt := "new-test-salt-for-rotation"

	// Encrypt data with original key
	dataBeforeRotation := "data encrypted before key rotation"
	encryptedBeforeRotation, err := svc.Encrypt(dataBeforeRotation)
	if err != nil {
		t.Fatalf("Encryption before key rotation failed: %v", err)
	}

	// Rotate the key
	err = svc.RotateKey(newKey, newSalt)
	if err != nil {
		t.Fatalf("Key rotation failed: %v", err)
	}

	// Encrypt data with new key
	dataAfterRotation := "data encrypted after key rotation"
	encryptedAfterRotation, err := svc.Encrypt(dataAfterRotation)
	if err != nil {
		t.Fatalf("Encryption after key rotation failed: %v", err)
	}

	// Decrypt data encrypted with new key
	decryptedAfterRotation, err := svc.Decrypt(encryptedAfterRotation)
	if err != nil {
		t.Fatalf("Decryption after key rotation failed: %v", err)
	}
	if decryptedAfterRotation != dataAfterRotation {
		t.Errorf("Expected decrypted data to be '%s', but got '%s'", dataAfterRotation, decryptedAfterRotation)
	}

	// Attempt to decrypt data encrypted with old key (should fail)
	_, err = svc.Decrypt(encryptedBeforeRotation)
	if err == nil {
		t.Errorf("Decryption of data encrypted with old key should fail after rotation")
	}
}
