package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
)

func createHash(key string) []byte {
	hash := sha256.Sum256([]byte(key))
	return hash[:]
}

func encryptData(data []byte, passphrase string) []byte {
	block, err := aes.NewCipher(createHash(passphrase))
	if err != nil {
		log.Fatal(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		log.Fatal(err)
	}

	encryptedData := gcm.Seal(nonce, nonce, data, nil)
	return encryptedData
}

func decryptData(data []byte, passphrase string) []byte {
	key := createHash(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		log.Fatal(err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		log.Fatal(err)
	}

	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	decryptedData, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Fatal(err)
	}
	return decryptedData
}

func encryptFile(inputFile string, outputFile string, passphrase string) {
	dataToEncrypt, err := ioutil.ReadFile(inputFile)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("New encrypted file will be created: ", outputFile+".crypt")
	fmt.Println("Old unencrypted file will be removed: ", inputFile)

	newFile, err := os.Create(outputFile + ".crypt")
	if err != nil {
		log.Fatal(err)
	}

	bytesWritten, err := newFile.Write(encryptData(dataToEncrypt, passphrase))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(bytesWritten, "bytes Written")

	newFile.Close()

	err = os.Remove(inputFile)
	if err != nil {
		log.Fatal(err)
	}
}

func decryptFile(encryptedFile string, decryptedFile string, passphrase string) {
	dataToDecrypt, err := ioutil.ReadFile(encryptedFile)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("New unencrypted file will be created: ", decryptedFile)

	newFile, err := os.Create(decryptedFile)
	if err != nil {
		log.Fatal(err)
	}

	dataDecrypted := decryptData(dataToDecrypt, passphrase)
	if err != nil {
		log.Fatal(err)
	}
	bytesWritten, err := newFile.Write(dataDecrypted)
	fmt.Println(bytesWritten, "bytes written")
	newFile.Close()
}

func printUsage() {
	fmt.Println("Usage example: gocrypter.exe -operation \"enc\" or \"dec\" -input \"filename\" -output \"newfilename\"")
}

func main() {
	argSlice := os.Args
	if len(argSlice) <= 1 {
		fmt.Println("No arguments provided")
		printUsage()
		os.Exit(1)
	}

	var operation string
	flag.StringVar(&operation, "operation", "", "Operation to perform, \"enc\" for encryption and \"dec\" for decryption")
	var input string
	flag.StringVar(&input, "input", "", "Name of input file")
	var output string
	flag.StringVar(&output, "output", "", "Name of output file")
	var password string
	flag.StringVar(&output, "password", "", "Password to use for encryption/decryption")
	flag.Parse()

	fmt.Println(operation)
	if operation == "enc" {
		encryptFile(input, output, password)
	} else if operation == "dec" {
		decryptFile(input, output, password)
	} else {
		fmt.Println("Operation not specified")
		printUsage()
		os.Exit(1)
	}
}
