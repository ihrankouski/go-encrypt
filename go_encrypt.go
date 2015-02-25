package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		panic("not enough arguments")
	}

	if os.Args[1] == "-d" {
		decrypt(os.Args[2:])
	} else {
		encrypt(os.Args[1:])
	}
}

func decrypt(args []string) {
	if len(args) < 2 {
		panic("not enough arguments")
	}
	key := args[0]
	encrypted := args[1]

	decrypted, err := DecryptStr_AES_CBC(encrypted, key)
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
}

func encrypt(args []string) {
	if len(args) < 2 {
		panic("not enough arguments")
	}
	key := args[0]
	original := args[1]

	encrypted, err := EncryptStr_AES_CBC(original, key)
	if err != nil {
		panic(err)
	}
	fmt.Println(encrypted)
}

//------------------------------------------------------------

// Encrypts string with AES (CBC) and encodes it in base64.
// IV will be included at the beginning of the ciphertext.
func EncryptStr_AES_CBC(s, key string) (encoded string, err error) {
	var ciphertext []byte
	if ciphertext, err = Encrypt_AES_CBC([]byte(s), []byte(key)); err != nil {
		return
	}

	encoded = base64.StdEncoding.EncodeToString(ciphertext)
	return
}

// Encrypts plaintext with AES (CBC)
// IV will be included at the beginning of the ciphertext.
func Encrypt_AES_CBC(plaintext, key []byte) (ciphertext []byte, err error) {
	if len(plaintext)%aes.BlockSize != 0 {
		plaintext = PKCS5Padding(plaintext, aes.BlockSize)
	}

	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext = make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	stream := cipher.NewCBCEncrypter(block, iv)
	stream.CryptBlocks(ciphertext[aes.BlockSize:], plaintext)
	return
}

// Decrypts base64 encoded AES (CBC) encrypted string
// IV must be included at the beginning of the ciphertext.
func DecryptStr_AES_CBC(s, key string) (decrypted string, err error) {
	var ciphertext []byte
	if ciphertext, err = base64.StdEncoding.DecodeString(s); err != nil {
		return
	}

	var plaintext []byte
	if plaintext, err = Decrypt_AES_CBC(ciphertext, []byte(key)); err != nil {
		return
	}

	decrypted = fmt.Sprintf("%s", plaintext)
	return
}

// Decrypts AES (CBC) encrypted data
// IV must be included at the beginning of the ciphertext
func Decrypt_AES_CBC(ciphertext, key []byte) (plaintext []byte, err error) {
	var block cipher.Block
	if block, err = aes.NewCipher(key); err != nil {
		return
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		err = fmt.Errorf("ciphertext too short")
		return
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		err = fmt.Errorf("ciphertext is not a multiple of the block size")
		return
	}

	plaintext = make([]byte, len(ciphertext))
	stream := cipher.NewCBCDecrypter(block, iv)
	stream.CryptBlocks(plaintext, ciphertext)
	plaintext = PKCS5UnPadding(plaintext)
	return
}

// http://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
func PKCS5Padding(text []byte, blockSize int) []byte {
	padding := blockSize - len(text)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(text, padtext...)
}

// http://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS7
func PKCS5UnPadding(text []byte) []byte {
	length := len(text)
	unpadding := int(text[length-1])

	// ensure text is padded
	if unpadding > length {
		return text
	}
	for i := length - 1; i >= length-unpadding; i-- {
		if int(text[i]) != unpadding {
			return text
		}
	}
	return text[:(length - unpadding)]
}
