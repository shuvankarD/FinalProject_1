package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
)

// Message struct represents the structure of a message
type Message struct {
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Content   string `json:"content"`
}

// User struct represents a user in the system
type User struct {
	Username string
	Password string // In a real system, this would be hashed and salted
}

// Database represents a simple in-memory database
type Database struct {
	Users []User
}

// Encrypt encrypts the message content using AES encryption
func Encrypt(key []byte, text string) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(text))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(text))

	return ciphertext, nil
}

// Decrypt decrypts the message content using AES decryption
func Decrypt(key, ciphertext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	text := ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(text, text)

	return string(text), nil
}

func main() {
	// Example usage
	key := []byte("example key 1234") // Key for AES encryption/decryption

	// Create a message
	msg := Message{
		Sender:    "Alice",
		Recipient: "Bob",
		Content:   "Hello, Bob! This is a secure message.",
	}

	// Convert message to JSON
	jsonData, err := json.Marshal(msg)
	if err != nil {
		fmt.Println("Error marshalling JSON:", err)
		return
	}

	// Encrypt the JSON data
	ciphertext, err := Encrypt(key, string(jsonData))
	if err != nil {
		fmt.Println("Error encrypting message:", err)
		return
	}

	// Example: store the ciphertext in a database

	// Decrypt the ciphertext
	decrypted, err := Decrypt(key, ciphertext)
	if err != nil {
		fmt.Println("Error decrypting message:", err)
		return
	}

	// Unmarshal JSON data into Message struct
	var receivedMsg Message
	err = json.Unmarshal([]byte(decrypted), &receivedMsg)
	if err != nil {
		fmt.Println("Error unmarshalling JSON:", err)
		return
	}

	// Print the received message
	fmt.Println("Received Message:")
	fmt.Println("Sender:", receivedMsg.Sender)
	fmt.Println("Recipient:", receivedMsg.Recipient)
	fmt.Println("Content:", receivedMsg.Content)
}
