package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide a valid auction id!")
		return
	}

	id, e := strconv.Atoi(arguments[1])
	if e != nil {
		fmt.Println("Enter a valid number please.")
		os.Exit(0)
	} else if id > GetLen()-1 {
		fmt.Println("To high! That auction does not exist.")
		os.Exit(0)
	}

	GetAuctionByID(id)
}

func GetLen() int {
	by, _ := os.ReadFile("privates.json")
	allPrivates := []Private{}
	_ = json.Unmarshal(by, &allPrivates)
	return len(allPrivates)
}

func GetAuctionByID(id int) {
	by, err := os.ReadFile("recordOfAuctions.json")
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	allAuctions := []Auction{}
	err = json.Unmarshal(by, &allAuctions)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}

	by2, err2 := os.ReadFile("privates.json")
	if err2 != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	allPrivates := []Private{}
	err = json.Unmarshal(by2, &allPrivates)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}

	chosenAuction := allAuctions[id]
	chosenPrivate := allPrivates[id]

	pKeyStr := strings.ReplaceAll(chosenPrivate.PrivateKey, "#", "\n")
	privateKey, _ := StringToRsaPrivateKey(pKeyStr)
	aucEmail := RSA_Decrypt(chosenAuction.AuctioneerEmail, *privateKey)
	var winnersDec []winnerInd
	for _, entry := range chosenAuction.ThingsAndWinners {
		th := RSA_Decrypt(entry.Thing, *privateKey)
		wi := RSA_Decrypt(entry.Winner, *privateKey)
		pr := RSA_Decrypt(entry.Price, *privateKey)
		winnersDec = append(winnersDec, winnerInd{Thing: th, Winner: wi, Price: pr})
	}
	decodedAuc := Auction{AuctionID: id, AuctioneerEmail: aucEmail, ThingsAndWinners: winnersDec}
	fmt.Println(decodedAuc)
}

type winnerInd struct {
	Thing  string `json:"thing"`
	Winner string `json:"winner"`
	Price  string `json:"price"`
}

type Auction struct {
	AuctionID        int         `json:"auctionID"`
	AuctioneerEmail  string      `json:"auctioneerEmail"`
	ThingsAndWinners []winnerInd `json:"thingsAndWinners"`
}

type Private struct {
	AuctionID  int    `json:"auctionID"`
	PrivateKey string `json:"privateKey"`
}

// CRYPTO FNS

func RSA_Encrypt(secretMessage string, key rsa.PublicKey) string {
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rng, &key, []byte(secretMessage), label)
	if err != nil {
		return "err"
	}
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func RSA_Decrypt(cipherText string, privKey rsa.PrivateKey) string {
	ct, _ := base64.StdEncoding.DecodeString(cipherText)
	label := []byte("OAEP Encrypted")
	rng := rand.Reader
	plaintext, _ := rsa.DecryptOAEP(sha256.New(), rng, &privKey, ct, label)
	return string(plaintext)
}

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
