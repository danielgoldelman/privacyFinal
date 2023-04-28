package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// current cost for thing on current auction
var cost int

// index of current auction
var ind int = 0

// All items going on bid
var itemlist []string

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

	// Array of all users' net connections
	uA := UserArr{
		cl: []net.Conn{},
	}

	// auctioneer net connections
	var sUConn net.Conn
	// auctioneer username
	var sUUser string

	// Accept auctioneer, deny client
	for {
		c, err := l.Accept()

		if err != nil {
			fmt.Println(err)
			return
		}

		// reads in first connection
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		temp := strings.TrimSpace(string(netData))

		if strings.HasPrefix(temp, "AUCTIONEER:") {
			// if the connection is the auctioneer

			// assign auctioneer's connection
			sUConn = c
			fmt.Println(temp)

			// splits auctioneer's info
			splitAuctioneerData := strings.Split(temp, ":")
			// gets auctioneer's username
			userName := splitAuctioneerData[1]
			sUUser = userName

			// gets auctioneer's denomination
			_ = splitAuctioneerData[2]

			// gets the thing, description, price list
			thingDescPrice := strings.Split(splitAuctioneerData[3], "~")
			itemlist = thingDescPrice

			message := "AUCTIONEER  " + userName + ":"

			fmt.Println(message)
			fmt.Println(thingDescPrice)

			// adds auctioneer to connection list
			uA.addCtoCL(c, userName)
			break
		} else {
			// first connection was not the auctioneer
			fmt.Fprintf(c, "Please wait for the auction to begin!")
			c.Close()
		}
	}

	splitThing := strings.Split(itemlist[ind], "@")
	cost, _ = strconv.Atoi(splitThing[2])

	// after auctioneer connects, run all following messages from the auctioneer on a new thread
	go uA.handleAuctioneerConnection(sUConn, sUUser)

	// for each new user (Clients)
	for {
		c, err := l.Accept()

		if err != nil {
			fmt.Println(err)
			return
		}

		// reads in first connection (will be username and denomination of the new connection)
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

		clientUnameDenom := strings.Split(temp, ":")

		// get client username
		clientUname := clientUnameDenom[1]

		// get client denomination
		_ = clientUnameDenom[2]
		fmt.Println("New Client: ", temp)

		// set up client in new thread
		go uA.handleClient(c, clientUname, itemlist)

		// add client to client list
		uA.addCtoCL(c, clientUname)
	}
}

type UserArr struct {
	cl []net.Conn
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
		if temp == "STOP" {
			discMess := "__Auctioneer " + userName + " disconnected__"
			fmt.Println(discMess)
			uA.sendAllElse(c, discMess)
			uA.deleteUser(c)
			break
		} else if temp == "NEXT" {
			fmt.Println("Next thing")
			ind += 1
			if ind == len(itemlist) {
				fmt.Fprintln(c, "Auction Terminated")
				break
			}
			splitThing := strings.Split(itemlist[ind], "@")
			cost, _ = strconv.Atoi(splitThing[2])

			mess := "Next thing on auction: " + splitThing[0] + "\tDescription: " + splitThing[1] + "\tStarting price: " + splitThing[2] + "\n"
			fmt.Println(mess)
			uA.sendAllElse(c, mess)
		} else {
			fmt.Fprintln(c, "Invalid input")
		}
		fmt.Println(temp)
	}
	uA.closeAll()
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

		temp := strings.TrimSpace(string(netData))

		// if the client disconnects
		if temp == "STOP" {
			discMess := "__User " + userName + " disconnected__"
			fmt.Println(discMess)

			// inform all other clients that this client has left
			uA.sendAllElse(c, discMess)

			// delete the user from the client list
			uA.deleteUser(c)
			break
		}

		n, _ := strconv.Atoi(temp)
		if n > cost {
			cost = n

			message := "User " + userName + ": " + temp

			fmt.Println(message)

			// inform all other clients of this client's new bid
			uA.sendAllElse(c, message)
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
}

// adds a connection to the UserArr
func (uA *UserArr) addCtoCL(c net.Conn, username string) {
	uA.cl = append(uA.cl, c)
}

func (uA *UserArr) closeAll() {
	for i := 0; i < len(uA.cl); i++ {
		conn := uA.cl[i]
		fmt.Fprintln(conn, "Auction Terminated")
		conn.Close()
	}
}
