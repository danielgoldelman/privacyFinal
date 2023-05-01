package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

func main() {
	privateKey, publicKey := GenerateRsaKeyPair()
	fmt.Println("private key: \n", privateKey)
	fmt.Print("\n")

	fmt.Println("public key: \n", publicKey)
	fmt.Print("\n")

	secretMessage := "This is a super secret password!"
	encryptedMessage := RSA_Encrypt(secretMessage, *publicKey)
	fmt.Println("Cipher of password: \n", encryptedMessage)
	fmt.Print("\n")

	decryptedMessage := RSA_Decrypt(encryptedMessage, *privateKey)
	fmt.Print("Decyphered password: \n", decryptedMessage)

	fmt.Print("\n")
	fmt.Print("\n")

	fmt.Print("###### Password encryption and decrpytion w/ salting functionalities #######")
	fmt.Print("\n")
	salt, _ := GenerateRandomString(16)
	fmt.Println("random salt string of length 16: \n", salt)
	fmt.Print("\n")

	salted_msg, salt := salt_msg(secretMessage, 16)
	fmt.Println("salted password: \n", salted_msg)
	fmt.Println("associated salt of length 16: \n", salt)
	fmt.Print("\n")

	encryptedMessage_w_salt, salt := Salt_and_RSA_Encrypt(secretMessage, 16, *publicKey)
	decryptedMessage_wo_salt := RSA_Decrypt_rmv_Salt(encryptedMessage_w_salt, salt, *privateKey)
	fmt.Print("\n")
	fmt.Println("encrypted salted secret password: ", encryptedMessage_w_salt)
	fmt.Print("\n")
	fmt.Println("encrypted secret password's salt: \n", salt)
	fmt.Print("\n")
	fmt.Println("decrypted secret password w/o salt: \n", decryptedMessage_wo_salt)
}

func CheckError(e error) {
	if e != nil {
		fmt.Println(e.Error())
	}
}

func GenerateRsaKeyPair() (*rsa.PrivateKey, *rsa.PublicKey) {
	privkey, _ := rsa.GenerateKey(rand.Reader, 2048)
	return privkey, &privkey.PublicKey
}

func RSA_Encrypt(secretMessage string, key rsa.PublicKey) string {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &key, []byte(secretMessage), label)
	CheckError(err)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func RSA_Decrypt(cipherText string, privKey rsa.PrivateKey) string {
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)
	CheckError(err)
	return string(plaintext)
}

func GenerateRandomString(n int) (string, error) {
	const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-!$^&*"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return "", err
		}
		ret[i] = chars[num.Int64()]
	}
	return string(ret), nil
}

func salt_msg(msg string, salt_len int) (string, string) {
	salt, _ := GenerateRandomString(salt_len)
	salted_msg := msg + salt
	return salted_msg, salt
}

func Salt_and_RSA_Encrypt(msg string, salt_len int, pubkey rsa.PublicKey) (string, string) {
	salted_msg, salt := salt_msg(msg, salt_len)
	encrypted_salted_msg := RSA_Encrypt(salted_msg, pubkey)
	return encrypted_salted_msg, salt
}

func RSA_Decrypt_rmv_Salt(encrypted_salted_msg string, salt string, privKey rsa.PrivateKey) string {
	decrypted_salted_msg := RSA_Decrypt(encrypted_salted_msg, privKey)
	decrypted_msg, _ := strings.CutSuffix(decrypted_salted_msg, salt)
	return decrypted_msg

}

func ExportRsaPrivateKeyAsPemStr(privkey *rsa.PrivateKey) string {
	privkey_bytes := x509.MarshalPKCS1PrivateKey(privkey)
	privkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privkey_bytes,
		},
	)
	return string(privkey_pem)
}

func ParseRsaPrivateKeyFromPemStr(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func ExportRsaPublicKeyAsPemStr(pubkey *rsa.PublicKey) (string, error) {
	pubkey_bytes, err := x509.MarshalPKIXPublicKey(pubkey)
	if err != nil {
		return "", err
	}
	pubkey_pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubkey_bytes,
		},
	)
	return string(pubkey_pem), nil
}

func ParseRsaPublicKeyFromPemStr(pubPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		break // fall through
	}
	return nil, errors.New("key type is not RSA")
}
