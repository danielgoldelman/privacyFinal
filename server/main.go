package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
)

var aucStarted bool = false

// current cost for thing on current auction
var cost int

// index of current auction
var ind int = 0

// name of current auction
var name string

// All items going on bid
var itemlist []string

// holders for public / private keys
var serverPublic *rsa.PublicKey
var serverPrivate *rsa.PrivateKey
var auctioneerPublic *rsa.PublicKey

// auctioneer net connections
var auctioneerConn net.Conn

// auctioneer username
var auctioneerUname string

// last person who bid (either higher or setup, no bid)
var lastBidder string = ""

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide a port number!")
		return
	}

	// Listens on the port specified by the server user
	PORT := ":" + arguments[1]
	l, err := net.Listen("tcp4", PORT)
	if err != nil {
		fmt.Println(err)
		return
	}
	// Closes the port completely after all connections close
	defer l.Close()

	serverPrivate, serverPublic = GenerateRsaKeyPair()

	// Array of all users' net connections
	uA := UserArr{
		cl: []net.Conn{},
		wl: []winnerInd{},
		ul: make(map[net.Conn]string),
	}

	// Accept auctioneer, deny client
	for {
		c, err := l.Accept()

		if err != nil {
			fmt.Println(err)
			return
		}

		// reads in first connection
		netData, err := bufio.NewReader(c).ReadString('#')
		if err != nil {
			fmt.Println(err)
			return
		}

		temp := strings.TrimSpace(string(netData))

		// decrypt the string, should start with AUCTIONEERPUB:
		if strings.HasPrefix(temp, "AUCTIONEERPUB:") {
			// if the connection is the auctioneer

			// assign auctioneer's connection
			auctioneerConn = c
			strA := temp[14 : len(temp)-2]
			aPub, _ := StringToRsaPublicKey(strA)
			auctioneerPublic = aPub
			sSPub, _ := RsaPublicKeyToString(serverPublic)

			// send server public key to client
			fmt.Fprint(auctioneerConn, "SERVERPUB:"+sSPub+"#")

			// reads in first connection
			netData, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				fmt.Println(err)
				return
			}

			temp := strings.TrimSpace(string(netData))

			// checking if the auctioneer sent their name, and list
			if strings.HasPrefix(temp, "AUCTIONEERNL:") {
				splitRet := strings.Split(temp, ":")
				uL := splitRet[1]
				salt := splitRet[2]

				auctioneerData := RSA_Decrypt_rmv_Salt(uL, salt, *serverPrivate)

				// splits auctioneer's info
				splitAuctioneerData := strings.Split(auctioneerData, ":")
				// gets auctioneer's username
				userName := splitAuctioneerData[0]
				auctioneerUname = userName

				// gets the thing, description, price list
				thingDescPrice := strings.Split(splitAuctioneerData[1], "~")
				itemlist = thingDescPrice

				fmt.Println("Auctioneer Entered")

				break
			} else {
				// should never happen
				fmt.Println("SOMETHING WENT WRONG")
				c.Close()
				os.Exit(0)
			}

		} else {
			// first connection was not the auctioneer
			fmt.Println("Client tried to connect too early")
			fmt.Fprintln(c, "Please wait for the auction to begin!")
			c.Close()
		}
	}

	splitThing := strings.Split(itemlist[ind], "#")
	// set first item name
	name = splitThing[0]
	// set first item cost
	cost, _ = strconv.Atoi(splitThing[2])

	// after auctioneer connects, run all following messages from the auctioneer on a new thread
	go uA.handleAuctioneerConnection(auctioneerConn, auctioneerUname)

	// for each new user (Clients)
	for {
		c, err := l.Accept()

		if err != nil {
			fmt.Println(err)
			return
		}

		// reads in first connection, should be the client saying hello
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		temp := strings.TrimSpace(string(netData))

		if strings.HasPrefix(temp, "AUCTIONEER:") {
			// another auctioneer tried to join
			fmt.Fprintf(c, "An auction has already begun!")
			c.Close()
			continue
		}

		if aucStarted {
			fmt.Fprintln(c, "An auction has already begun!")
			c.Close()
			continue
		}

		// now that we know this is a client, run this client on its own thread to not slow down any other new connections
		go func() {

			sSPub, _ := RsaPublicKeyToString(serverPublic)

			// send server public key to client
			fmt.Fprintln(c, "SERVERPUB:"+sSPub+"#")

			netData2, err2 := bufio.NewReader(c).ReadString('\n')
			if err2 != nil {
				fmt.Println(err)
				return
			}

			temp2 := strings.TrimSpace(string(netData2))

			// get username from client
			splitRet2 := strings.Split(temp2, ":")
			strAndUnameEnc := splitRet2[1]
			salt2 := splitRet2[2]

			strAndUname := RSA_Decrypt_rmv_Salt(strAndUnameEnc, salt2, *serverPrivate)

			clientUname := strings.Split(strAndUname, ":")[1]

			fmt.Println("New Client")

			// set up client in new thread
			// client name is the number of their connection
			go uA.handleClient(c, strconv.Itoa(len(uA.cl)), itemlist)

			// add client to client list
			uA.addCtoCL(c, clientUname)
		}()
	}

}

// individual winner object
type winnerInd struct {
	Thing  string `json:"thing"`
	Winner string `json:"winner"`
}

// general type to hold client list (list of connections), winner list (list of (item name * winner name)), and user list (map from net.conn to username)
type UserArr struct {
	cl []net.Conn
	wl []winnerInd
	ul map[net.Conn]string
}

// Generates new read, handles disconnection
func (uA *UserArr) handleAuctioneerConnection(c net.Conn, userName string) {
	for {
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		temp := strings.TrimSpace(string(netData))
		fmt.Println(temp)
		if temp == "STOP" && aucStarted {
			discMess := "__Auctioneer disconnected__"
			fmt.Println(discMess)
			uA.sendAllElse(c, discMess)

			// get last winner
			uA.wl = append(uA.wl, winnerInd{Thing: name, Winner: lastBidder})
			winnerList := winnersToString(uA.wl)
			encryptedMessage, salt := Salt_and_RSA_Encrypt(winnerList, 16, *auctioneerPublic)

			// Send winner list to auctioneer, encrypted with their public key
			fmt.Fprintln(c, "STOPRET:"+encryptedMessage+":"+salt)

			// encrypt everything for long term storage
			aucEmailEncrypted := RSA_Encrypt(auctioneerUname, *serverPublic)
			var encryptedwl []winnerInd
			for _, entry := range uA.wl {
				thingEnc := RSA_Encrypt(entry.Thing, *serverPublic)
				winnerEnc := RSA_Encrypt(entry.Winner, *serverPublic)
				new := winnerInd{Thing: thingEnc, Winner: winnerEnc}
				encryptedwl = append(encryptedwl, new)
			}

			// add to lts
			AppendToRecords(Auction{AuctionID: 0, AuctioneerEmail: aucEmailEncrypted, ThingsAndWinners: encryptedwl})
			serverPrivateString, _ := RsaPrivateKeyToString(serverPrivate)
			// have to remove all instances of '\n', so replace with '#'
			serverPrivateStringLnToHash := strings.ReplaceAll(serverPrivateString, "\n", "#")
			AppendToPrivates(Private{AuctionID: 0, PrivateKey: serverPrivateStringLnToHash})
			break
		} else if temp == "NEXT" && aucStarted {
			fmt.Println("Next thing")
			uA.wl = append(uA.wl, winnerInd{Thing: name, Winner: lastBidder})
			lastBidder = ""
			ind += 1
			if ind == len(itemlist) {
				fmt.Fprintln(c, "Auction Terminated")

				// see the winner list on the server
				fmt.Println(uA.wl)
				winnerList := winnersToString(uA.wl)
				encryptedMessage, salt := Salt_and_RSA_Encrypt(winnerList, 16, *auctioneerPublic)

				// Send winner list to client, encrypted with their public key
				fmt.Fprintln(c, encryptedMessage+":"+salt)

				aucEmailEncrypted := RSA_Encrypt(auctioneerUname, *serverPublic)
				var encryptedwl []winnerInd
				for _, entry := range uA.wl {
					thingEnc := RSA_Encrypt(entry.Thing, *serverPublic)
					winnerEnc := RSA_Encrypt(entry.Winner, *serverPublic)
					new := winnerInd{Thing: thingEnc, Winner: winnerEnc}
					encryptedwl = append(encryptedwl, new)
				}

				// add to lts
				AppendToRecords(Auction{AuctionID: 0, AuctioneerEmail: aucEmailEncrypted, ThingsAndWinners: encryptedwl})
				serverPrivateString, _ := RsaPrivateKeyToString(serverPrivate)
				// have to remove all instances of '\n', so replace with '#'
				serverPrivateStringLnToHash := strings.ReplaceAll(serverPrivateString, "\n", "#")
				AppendToPrivates(Private{AuctionID: 0, PrivateKey: serverPrivateStringLnToHash})
				break
			}

			// setup new item for bid
			splitThing := strings.Split(itemlist[ind], "#")
			name = splitThing[0]
			cost, _ = strconv.Atoi(splitThing[2])

			// inform all clients of next thing on auction
			mess := "Next thing on auction: " + splitThing[0] + "$Description: " + splitThing[1] + "$Starting price: " + splitThing[2]
			fmt.Println(mess)
			uA.sendAllElse(c, mess)
		} else if temp == "START" && !aucStarted {
			aucStarted = true
			fmt.Println("First thing")
			// setup new item for bid
			splitThing := strings.Split(itemlist[ind], "#")
			name = splitThing[0]
			cost, _ = strconv.Atoi(splitThing[2])

			// inform all clients of next thing on auction
			mess := "First thing on auction: " + splitThing[0] + "$Description: " + splitThing[1] + "$Starting price: " + splitThing[2]
			fmt.Println(mess)
			uA.sendAllElse(c, mess)
		} else {
			fmt.Println(temp, aucStarted)
			fmt.Fprintln(c, "Invalid input")
		}
		fmt.Println(temp)
	}
	uA.sendAllElse(c, "Auction Terminated")
	c.Close()
	os.Exit(0)
}

// Generates new read, handles disconnection, sends the message to all other connections
func (uA *UserArr) handleClient(c net.Conn, userName string, itemList []string) {
	fmt.Fprintln(c, "Welcome! List of items:", itemList)

	for {
		// on new message from this client
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		if !aucStarted {
			fmt.Fprintln(c, "Auction has not yet begun.")
			continue
		}

		temp := strings.TrimSpace(string(netData))
		fmt.Println(temp)

		// if the client disconnects
		if temp == "STOP" {
			fmt.Println("instop")
			discMess := "__User " + userName + " disconnected__"
			fmt.Println(discMess)

			fmt.Fprintln(c, "bye")

			// inform all other clients that this client has left
			uA.sendAllElse(c, discMess)
			sendToAuc(discMess)

			// delete the user from the client list
			uA.deleteUser(c)
			break
		}

		n, _ := strconv.Atoi(temp)
		if n > cost {
			cost = n

			message := "User " + userName + ": " + temp

			fmt.Println(message)

			lastBidder = uA.ul[c]

			// inform all other clients of this client's new bid
			uA.sendAllElse(c, message)
			sendToAuc(message)
		} else {
			fmt.Fprintln(c, "Current cost is", cost, ", so your bid is too low. Increase bid.")
		}
	}
	c.Close()
}

// given the UserArr, a connection, and a message, sends the message to all connections != c
func (uA *UserArr) sendAllElse(c net.Conn, message string) {
	for _, v := range uA.cl {
		if v != c {
			fmt.Fprintln(v, message)
		}
	}
}

// send a message to the auctioneer
func sendToAuc(message string) {
	fmt.Fprintln(auctioneerConn, message)
}

// deletes a connection from the UserArr
func (uA *UserArr) deleteUser(c net.Conn) {
	var idx int
	for i := 0; i < len(uA.cl); i++ {
		if uA.cl[i] == c {
			idx = i
			break
		}
	}
	uA.cl = append(uA.cl[:idx], uA.cl[idx+1:]...)
	delete(uA.ul, c)
}

// adds a connection to the UserArr
func (uA *UserArr) addCtoCL(c net.Conn, username string) {
	uA.cl = append(uA.cl, c)
	uA.ul[c] = username
}

func winnersToString(wl []winnerInd) string {
	var listAsString string
	for _, thingWinner := range wl {
		listAsString += `{"Thing":"` + thingWinner.Thing + `","Winner":"` + thingWinner.Winner + `"},`
	}
	return "[" + listAsString[0:len(listAsString)-1] + "]"
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

// SAVING FUNCTIONS, TYPES

type Auction struct {
	AuctionID        int         `json:"auctionID"`
	AuctioneerEmail  string      `json:"auctioneerEmail"`
	ThingsAndWinners []winnerInd `json:"thingsAndWinners"`
}

func AppendToRecords(newAuction Auction) {
	filePath := "recordOfAuctions.json"
	by, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	c := []Auction{}
	err = json.Unmarshal(by, &c)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}

	newAuction.AuctionID = len(c)

	c = append(c, newAuction)

	// convert Person object to a JSON byte slice
	jsonBytes, err := json.Marshal(c)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}

	// write JSON data to file, overwriting if it already exists
	err = os.WriteFile(filePath, jsonBytes, 0644)
	if err != nil {
		fmt.Println("Error writing JSON file:", err)
	}
}

type Private struct {
	AuctionID  int    `json:"auctionID"`
	PrivateKey string `json:"privateKey"`
}

func AppendToPrivates(newPrivate Private) {
	filePath := "privates.json"
	by, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Println("Error reading file:", err)
		return
	}

	c := []Private{}
	err = json.Unmarshal(by, &c)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return
	}

	newPrivate.AuctionID = len(c)

	c = append(c, newPrivate)

	// convert Person object to a JSON byte slice
	jsonBytes, err := json.Marshal(c)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}

	// write JSON data to file, overwriting if it already exists
	err = os.WriteFile(filePath, jsonBytes, 0644)
	if err != nil {
		fmt.Println("Error writing JSON file:", err)
	}
}
