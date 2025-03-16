package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/pbkdf2"
)

const (
	privateKeyFile      = "orbitdb_private.pem"   // Define a constant for the private key file name
	encryptedAESKeyFile = "encrypted_aes_key.bin" // File to store the encrypted AES key
	saltSize            = 16                      // Size of the random salt in bytes
)

// generateRandomSalt generates a random salt of specified size.
func generateRandomSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// generatePrivateKey generates an RSA private key and saves it to a file.
func generatePrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048) // You can adjust the key size
	if err != nil {
		return nil, err
	}

	// Convert private key to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}

	// Create the private key file
	file, err := os.Create(privateKeyFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Write the private key to the file
	err = pem.Encode(file, privateKeyBlock)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// loadPrivateKey loads an RSA private key from a file.
func loadPrivateKey() (*rsa.PrivateKey, error) {
	privateKeyFileBytes, err := os.ReadFile(privateKeyFile)
	if err != nil {
		return nil, err
	}

	privateKeyBlock, _ := pem.Decode(privateKeyFileBytes)
	if privateKeyBlock == nil {
		return nil, err
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// getPrivateKey retrieves the private key, generating it if it doesn't exist.
func getPrivateKey() (*rsa.PrivateKey, error) {
	if _, err := os.Stat(privateKeyFile); os.IsNotExist(err) {
		return generatePrivateKey()
	}
	return loadPrivateKey()
}

// deriveAESKey derives an AES key from a password using PBKDF2.
func deriveAESKey() ([]byte, error) {
	password := os.Getenv("ENC_PASSWORD") // Retrieve the password from the environment variable
	if password == "" {
		return nil, errors.New("no password found in environment variable")
	}
	salt, err := generateRandomSalt(saltSize)
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key([]byte(password), []byte(salt), 10000, 32, sha256.New), nil // 32 bytes for AES-256
}

// saveAesKey saves the AES key, generating it if it doesn't exist.
func saveAesKey() error {
	if _, err := os.Stat(encryptedAESKeyFile); os.IsNotExist(err) {
		aesKey, err := deriveAESKey()
		if err != nil {
			return err
		}

		// Encrypt the AES key with RSA for storage.
		privateKey, err := getPrivateKey()
		if err != nil {
			return err
		}

		encryptedAESKeyBytes, err := rsa.EncryptPKCS1v15(rand.Reader, &privateKey.PublicKey, aesKey)
		if err != nil {
			return err
		}

		// Store the encrypted AES key in a file.
		if err = os.WriteFile(encryptedAESKeyFile, encryptedAESKeyBytes, 0644); err != nil {
			return err
		}

		return nil // Return the newly generated AES key
	}
	return nil
}

func main() {
	err := saveAesKey()
	if err != nil {
		log.Fatal(err)
	}
}
