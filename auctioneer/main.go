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

// holders for public / private keys
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

	auctioneerPublicAsString, _ := RsaPublicKeyToString(auctioneerPublic)

	fmt.Fprint(c, "AUCTIONEERPUB:"+auctioneerPublicAsString+"#")
	message, _ := bufio.NewReader(c).ReadString('#')
	mess := strings.TrimSpace(string(message))
	if mess == "An auction has already begun!" {
		fmt.Print(mess)
		c.Close()
		os.Exit(0)
	} else {
		temp := message[10 : len(message)-1]
		sSPub, _ := StringToRsaPublicKey(temp)
		serverPublic = sSPub
	}

	scanner := bufio.NewScanner(os.Stdin)

	// new array to hold auctioneer name
	var aucName string
	for {
		fmt.Print("Auctioneer Name: ")
		// Scans a line from Stdin(Console)
		scanner.Scan()
		// Holds the string that scanned
		text := scanner.Text()
		if len(text) != 0 {
			aucName = text
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
	for i := 1; i <= numThings; i++ {
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
					arrIndiv = append(arrIndiv, strconv.Itoa(n))
					break
				}
			}
			fmt.Println("Try Again!")
		}

		// takes item, description, price, and makes it a string broken up by the # symbol
		formatIndiv := strings.Join(arrIndiv, "#")

		// appends the above string to the list of things being auctioned
		arrT = append(arrT, formatIndiv)

		fmt.Print("\n\n")
	}

	formatarrT := strings.Join(arrT, "~")

	// full encryption of the username, thing list

	nameList := aucName + ":" + formatarrT
	encryptedMessage, salt := Salt_and_RSA_Encrypt(nameList, 16, *serverPublic)

	fmt.Fprintln(c, "AUCTIONEERNL:"+encryptedMessage+":"+salt)

	go auctioneerSend(c)

	// reads from server, prints server send
	for {
		message, _ := bufio.NewReader(c).ReadString('\n')
		mess := strings.TrimSpace(string(message))
		if mess == "An auction has already begun!" {
			break
		} else if mess == "Auction Terminated" {
			netData, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				fmt.Println(err)
				return
			}

			temp := strings.TrimSpace(string(netData))

			splitRet := strings.Split(temp, ":")
			winnerListEncrypted := splitRet[0]
			salt := splitRet[1]

			winnerData := RSA_Decrypt_rmv_Salt(winnerListEncrypted, salt, *auctioneerPrivate)
			fmt.Println(winnerData)
			break
		} else if strings.HasPrefix(mess, "STOPRET:") {
			splitRet := strings.Split(mess, ":")
			winnerListEncrypted := splitRet[1]
			salt := splitRet[2]

			winnerData := RSA_Decrypt_rmv_Salt(winnerListEncrypted, salt, *auctioneerPrivate)
			fmt.Println(winnerData)

			os.Exit(0)
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
			// Scans a line from Stdin(Console)
			scanner.Scan()
			// Holds the string that scanned
			text := scanner.Text()

			// Client wants to exit the auction
			message := strings.TrimSpace(string(text))
			if message == "STOP" || message == "NEXT" || message == "START" {
				mess = message
				break
			} else {
				fmt.Println("Try Again!")
			}
		}

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

// Function to convert an RSA private key to a string
func RsaPrivateKeyToString(privKey *rsa.PrivateKey) (string, error) {
	// Marshal the private key into DER format
	derBytes := x509.MarshalPKCS1PrivateKey(privKey)

	// Encode the DER bytes in PEM format
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: derBytes,
	})

	// Convert the PEM bytes to a string and return it
	return string(pemBytes), nil
}

// Function to convert a string to an RSA private key
func StringToRsaPrivateKey(privKeyString string) (*rsa.PrivateKey, error) {
	// Decode the PEM-encoded private key string
	block, _ := pem.Decode([]byte(privKeyString))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	// Parse the DER-encoded private key bytes
	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

// Function to convert an RSA public key to a string
func RsaPublicKeyToString(pubKey *rsa.PublicKey) (string, error) {
	// Marshal the public key into DER format
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", err
	}

	// Encode the DER bytes in PEM format
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derBytes,
	})

	// Convert the PEM bytes to a string and return it
	return string(pemBytes), nil
}

// StringToPublicKey converts a string to an RSA public key.
func StringToRsaPublicKey(pubStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubStr))
	if block == nil {
		return nil, errors.New("failed to parse PEM block containing the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("key type is not RSA")
	}

	return rsaPub, nil
}
