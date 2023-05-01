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
	"log"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
)

var serverPublic *rsa.PublicKey

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide host:port.")
		return
	}

	CONNECT := arguments[1]
	c, err := net.Dial("tcp", CONNECT)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Fprintln(c, "Client#")
	fmt.Println("The auction will begin shortly.")

	message, _ := bufio.NewReader(c).ReadString('#')
	messTrimmed := strings.TrimSpace(string(message))
	if messTrimmed == "Please wait for the auction to begin!" {
		fmt.Println(messTrimmed)
		c.Close()
		os.Exit(0)
	}
	temp := messTrimmed[10 : len(messTrimmed)-1]
	sSPub, _ := StringToRsaPublicKey(temp)
	serverPublic = sSPub

	// serverPublic, _ = StringToRsaPublicKey(getFromFile("serverPublic.txt"))

	scanner := bufio.NewScanner(os.Stdin)
	var uName string
	var uDenom string
	for {
		fmt.Print("Client Name: ")
		// Scans a line from Stdin(Console)
		scanner.Scan()
		// Holds the string that scanned
		text := scanner.Text()
		if len(text) != 0 {
			uName = text
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
			uDenom = text
			break
		}
		fmt.Println("Try Again!")
	}

	nameDenom := "Username:" + uName + ":" + uDenom
	encryptedMessage, salt := Salt_and_RSA_Encrypt(nameDenom, 16, *serverPublic)

	fmt.Fprintln(c, "CLIENTND:"+encryptedMessage+":"+salt)

	// starts separate thread for this for loop

	// takes in user input, sends to server
	go runClient(c)

	// reads from server, prints server send
	for {
		message, _ := bufio.NewReader(c).ReadString('\n')
		messTrimmed := strings.TrimSpace(string(message))
		if messTrimmed == "Please wait for the auction to begin!" {
			c.Close()
			os.Exit(0)
		} else if messTrimmed == "Auction Terminated" {
			fmt.Println(messTrimmed)
			c.Close()
			os.Exit(0)
		} else if messTrimmed == "bye" {
			c.Close()
			os.Exit(0)
		} else if strings.HasPrefix(messTrimmed, "Welcome") {
			fmt.Print("\n\n")
			for _, msg := range strings.Split(messTrimmed, "$") {
				fmt.Println(msg)
			}
			fmt.Print("\n\n")
		} else if strings.HasPrefix(messTrimmed, "Next thing on auction") {
			fmt.Print("\n\n")
			for _, msg := range strings.Split(messTrimmed, "$") {
				fmt.Println(msg)
			}
			fmt.Print("\n\n")
		} else {
			fmt.Println(messTrimmed)
		}
	}
}

func runClient(c net.Conn) {
	for {
		var num int
		scanner := bufio.NewScanner(os.Stdin)
		for {
			// Scans a line from Stdin(Console)
			scanner.Scan()
			// Holds the string that scanned
			text := scanner.Text()

			// Client wants to exit the auction
			if strings.TrimSpace(string(text)) == "STOP" {
				fmt.Println("Disconnecting...")
				fmt.Fprintln(c, "STOP")
				return
			}

			// ensures the client used an integer
			if len(text) != 0 {
				if n, e := strconv.Atoi(text); e == nil {
					num = n
					break
				}
			}
			fmt.Println("Try Again!")
		}

		// only sends to server if the client input a number
		fmt.Fprintln(c, fmt.Sprint(num))
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

func getFromFile(filename string) string {
	// Open the file for reading
	data, err := os.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
	}
	return string(data)
}
