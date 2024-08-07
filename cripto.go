package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func encryptAccessKey(key string) (string, error) {
	aesKey := "J2DjYOnTY6Bo+N3GXXGwkooj"
	nonce := []byte("123456789987")
	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		return "", fmt.Errorf("failed to create new cipher block: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create new GCM: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(key), nil)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func decryptAccessKey(key string) (string, error) {
	aesKey := "J2DjYOnTY6Bo+N3GXXGwkooj"
	nonce := []byte("123456789987")
	block, err := aes.NewCipher([]byte(aesKey))
	if err != nil {
		return "", fmt.Errorf("failed to create new cipher block: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("failed to create new GCM block: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 string: %w", err)
	}

	plainText, err := aesgcm.Open(nil, nonce, ciphertext[len(nonce):], nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt ciphertext: %w", err)
	}

	return string(plainText), nil
}

func main() {
	fmt.Println("Starting the application...")
	ciphertext, _ := encryptAccessKey("biscoito")
	fmt.Printf("Encrypted: %x\n", ciphertext)
	plaintext, _ := decryptAccessKey(ciphertext)
	fmt.Printf("Decrypted: %s\n", plaintext)
}
