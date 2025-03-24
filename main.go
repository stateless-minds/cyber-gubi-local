package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"

	shell "github.com/stateless-minds/go-ipfs-api"
	"golang.org/x/crypto/pbkdf2"
)

const (
	dbUserDevice        = "user_device"
	encryptedAESKeyFile = "encrypted_aes_key.bin" // File to store the encrypted AES key
	saltSize            = 16                      // Size of the random salt in bytes
)

type UserDevice struct {
	ID         string `mapstructure:"_id" json:"_id" validate:"uuid_rfc4122"`               // Unique identifier for device
	Address    string `mapstructure:"address" json:"address" validate:"uuid_rfc4122"`       // Key for device
	Registered bool   `mapstructure:"registered" json:"registered" validate:"uuid_rfc4122"` // Check if registered
}

// generateRandomSalt generates a random salt of specified size.
func generateRandomSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
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

// Get the MAC address of the host machine
func getMacAddr() (addr string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Fatal(err)
	}

	for _, i := range interfaces {
		if i.Flags&net.FlagUp != 0 && len(i.HardwareAddr) > 0 {
			addr = i.HardwareAddr.String()
			break
		}
	}

	return
}

// Hash the MAC address using SHA-256
func hashMacAddr(macAddr string) string {
	hash := sha256.Sum256([]byte(macAddr))
	return hex.EncodeToString(hash[:])
}

// Encrypt the AES key using the hashed MAC address as the encryption key
func encryptAESKey(aesKey []byte, hashKey string) ([]byte, error) {
	// Convert the hash key to a byte array
	key, _ := hex.DecodeString(hashKey)

	// Create a new AES cipher block
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create a GCM (Galois/Counter Mode) for authenticated encryption
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the AES key
	encrypted := gcm.Seal(nonce, nonce, aesKey, nil)
	return encrypted, nil
}

// getAesKey saves the AES key, generating it if it doesn't exist.
func getAesKey(hashedMacAddr string) ([]byte, error) {
	aesKey, err := deriveAESKey()
	if err != nil {
		return nil, err
	}

	// Encrypt the AES key
	encryptedAESKey, err := encryptAESKey(aesKey, hashedMacAddr)
	if err != nil {
		return nil, err
	}

	// Store the encrypted AES key in a file.
	if err = os.WriteFile(encryptedAESKeyFile, encryptedAESKey, 0644); err != nil {
		return nil, err
	}

	return encryptedAESKey, nil // Return the newly generated AES key
}

func deleteDevices(sh *shell.Shell) error {
	err := sh.OrbitDocsDelete(dbUserDevice, "all")
	if err != nil {
		return err
	}
	return nil
}

func getDevices(sh *shell.Shell) []UserDevice {
	devices, err := sh.OrbitDocsQuery(dbUserDevice, "all", "")
	if err != nil {
		log.Fatal(err)
	}

	if string(devices) == "" {
		return []UserDevice{}
	}

	var userDevices []UserDevice

	err = json.Unmarshal([]byte(devices), &userDevices) // Unmarshal the byte slice directly
	if err != nil {
		log.Fatal(err)
	}

	return userDevices
}

func main() {
	sh := shell.NewShell("localhost:5001")

	// devices := getDevices(sh)
	// log.Println(devices)
	// err = deleteDevices(sh)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// return

	macAddr := getMacAddr()

	var hashedMacAddr string
	if macAddr != "" {
		hashedMacAddr = hashMacAddr(macAddr)
	} else {
		log.Fatal("no mac address found")
	}

	data, err := ioutil.ReadFile(encryptedAESKeyFile)
	if err != nil {
		log.Println("user doesn't exist, storing")
		aesKey, err := getAesKey(hashedMacAddr)
		if err != nil {
			log.Fatal(err)
		}

		device := UserDevice{
			ID:         hex.EncodeToString(aesKey),
			Address:    hashedMacAddr,
			Registered: false,
		}

		data, err := json.Marshal(device)
		if err != nil {
			log.Fatal(err)
		}

		log.Println("data: ", string(data))

		err = sh.OrbitDocsPut(dbUserDevice, data)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	// find by key
	device, err := sh.OrbitDocsGet(dbUserDevice, hex.EncodeToString(data))
	if err != nil {
		log.Fatal(err)
	}

	var userDevice []UserDevice

	err = json.Unmarshal([]byte(device), &userDevice) // Unmarshal the byte slice directly
	if err != nil {
		log.Fatal(err)
	}

	log.Println("userDevice: ", userDevice)

	// empty
	if len(userDevice) == 0 {
		log.Fatal(errors.New("unknown key"))
	} else {
		if userDevice[0].Address == hashedMacAddr {
			log.Println("user exists, file exists, device matches")
			return
		} else {
			aesKey, err := getAesKey(hashedMacAddr)
			if err != nil {
				log.Fatal(err)
			}
			log.Println("user is on a new device")
			// user is attemtping to register from a new device
			device := UserDevice{
				ID:         hex.EncodeToString(aesKey),
				Address:    hashedMacAddr,
				Registered: userDevice[0].Registered,
			}

			data, err := json.Marshal(device)
			if err != nil {
				log.Fatal(err)
			}

			err = sh.OrbitDocsPut(dbUserDevice, data)
			if err != nil {
				log.Fatal(err)
			}
		}
	}
}
