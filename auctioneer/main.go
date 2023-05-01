package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
)

var auctioneerPublic *rsa.PublicKey
var auctioneerPrivate *rsa.PrivateKey
var serverPublic *rsa.PublicKey

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide host:port.")
		return
	}

	// requires a ip:port
	CONNECT := arguments[1]
	c, err := net.Dial("tcp", CONNECT)
	if err != nil {
		fmt.Println(err)
		return
	}

	auctioneerPrivate, auctioneerPublic = GenerateRsaKeyPair()

	scanner := bufio.NewScanner(os.Stdin)

	// new array to hold auctioneer name, auctioneer denomination
	arr := make([]string, 0)
	for {
		fmt.Print("Auctioneer Name: ")
		// Scans a line from Stdin(Console)
		scanner.Scan()
		// Holds the string that scanned
		text := scanner.Text()
		if len(text) != 0 {
			arr = append(arr, text)
			break
		}
		fmt.Println("Try Again!")
	}
	for {
		fmt.Print("Enter Denomination: ")
		// Scans a line from Stdin(Console)
		scanner.Scan()
		// Holds the string that scanned
		text := scanner.Text()
		if len(text) != 0 {
			arr = append(arr, text)
			break
		}
		fmt.Println("Try Again!")
	}

	numThings := 0

	for {
		fmt.Print("Enter Number of Things: ")
		// Scans a line from Stdin(Console)
		scanner.Scan()
		// Holds the string that scanned
		text := scanner.Text()

		// ensures the auctioneer used an integer
		if len(text) != 0 {
			if n, e := strconv.Atoi(text); e == nil {
				numThings = n
				break
			}
		}
		fmt.Println("Try Again!")
	}

	// takes in user input, sends to server
	arrT := make([]string, 0)
	for i := 0; i < numThings; i++ {
		arrIndiv := make([]string, 0)
		for {
			fmt.Print("Enter Thing: ")
			// Scans a line from Stdin(Console)
			scanner.Scan()
			// Holds the string that scanned
			text := scanner.Text()
			if len(text) != 0 {
				arrIndiv = append(arrIndiv, text)
				break
			}
			fmt.Println("Try Again!")
		}
		for {
			fmt.Print("Enter Description: ")
			// Scans a line from Stdin(Console)
			scanner.Scan()
			// Holds the string that scanned
			text := scanner.Text()
			if len(text) != 0 {
				arrIndiv = append(arrIndiv, text)
				break
			}
			fmt.Println("Try Again!")
		}
		for {
			fmt.Print("Enter Price: ")
			// Scans a line from Stdin(Console)
			scanner.Scan()
			// Holds the string that scanned
			text := scanner.Text()

			// ensures the auctioneer used an integer
			if len(text) != 0 {
				if n, e := strconv.Atoi(text); e == nil {
					numThings = n
					arrIndiv = append(arrIndiv, text)
					break
				}
			}
			fmt.Println("Try Again!")
		}

		// takes item, description, price, and makes it a string broken up by the # symbol
		formatIndiv := strings.Join(arrIndiv, "#")

		// appends the above string to the list of things being auctioned
		arrT = append(arrT, formatIndiv)

		fmt.Print("\n\n\n")
	}

	formatarrT := strings.Join(arrT, "~")

	// full encryption of the username, denom, thing list

	fmt.Fprint(c, "AUCTIONEER:"+arr[0]+":"+arr[1]+":"+formatarrT+"\n")

	go auctioneerSend(c)

	// reads from server, prints server send
	for {
		message, _ := bufio.NewReader(c).ReadString('\n')
		mess := strings.TrimSpace(string(message))
		if mess == "An auction has already begun!" {
			break
		} else if mess == "Auction Terminated" {
			break
		}
		fmt.Print(message)
	}
	c.Close()
	os.Exit(0)
}

func auctioneerSend(c net.Conn) {
	for {
		var mess string
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("\n")
			// Scans a line from Stdin(Console)
			scanner.Scan()
			// Holds the string that scanned
			text := scanner.Text()

			// Client wants to exit the auction
			message := strings.TrimSpace(string(text))
			if message == "STOP" {
				fmt.Println("TCP client exiting...")
				os.Exit(0)
			} else if message == "NEXT" {
				mess = message
				break
			}
			fmt.Println("Try Again!")
		}

		// only sends to server if the client input a number
		fmt.Fprintln(c, fmt.Sprint(mess))
	}
}

// CRYPTO FUNCTIONS

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
