package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {

	var (
		key string
		textin string
		decrypt bool
	)

	flag.BoolVar(&decrypt, "d", false, "Set to decrypt text")
	flag.StringVar(&key, "k", "", "16, 24, or 32 characters")
	flag.StringVar(&textin, "t", "", "Not empty string")
	flag.Parse()

	keyLength := len(key)
	switch {
	case keyLength != 16 && keyLength != 24 && keyLength != 32:
		fallthrough
	case len(textin) == 0:
		flag.Usage()
		os.Exit(2)
	}

	var (
		err error
		textout string
	)

	if decrypt {
		textout, err = DecryptStr_AES_CBC(textin, key)
	} else {
		textout, err = EncryptStr_AES_CBC(textin, key)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(textout)
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
