package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

var cost int

func main() {
	arguments := os.Args
	if len(arguments) == 1 {
		fmt.Println("Please provide a port number!")
		return
	}

	PORT := ":" + arguments[1]
	l, err := net.Listen("tcp4", PORT)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	uA := UserArr{
		cl: []net.Conn{},
	}

	var sUConn net.Conn
	var sUUser string

	var itemlist []string

	// Accept superuser, deny client
	for {
		c, err := l.Accept()

		if err != nil {
			fmt.Println(err)
			return
		}

		// reads in first connection (will be username of the new connection)
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		temp := strings.TrimSpace(string(netData))

		if strings.HasPrefix(temp, "SUPERUSER:") {
			sUConn = c
			fmt.Println(temp)
			splitSuperuserData := strings.Split(temp, ":")
			userName := splitSuperuserData[1]
			sUUser = userName
			_ = splitSuperuserData[2]
			thingDescPrice := strings.Split(splitSuperuserData[3], "~")
			itemlist = thingDescPrice

			message := "SUPERUSER  " + userName + ":"

			fmt.Println(message)
			fmt.Println(thingDescPrice)

			uA.addCtoCL(c, userName)
			break
		} else {
			fmt.Fprintf(c, "Please wait for the auction to begin!")
			c.Close()
		}
	}

	go uA.handleSuperuserConnection(sUConn, sUUser)

	// for each new user (Clients)
	for {
		c, err := l.Accept()

		if err != nil {
			fmt.Println(err)
			return
		}

		// reads in first connection (will be username of the new connection)
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		temp := strings.TrimSpace(string(netData))
		clientUnameDenom := strings.Split(temp, ":")
		clientUname := clientUnameDenom[1]
		_ = clientUnameDenom[2]
		fmt.Println("New Client: ", temp)

		go uA.handleClient(c, clientUname, itemlist)
		uA.addCtoCL(c, temp)
	}
}

type UserArr struct {
	cl []net.Conn
}

// Generates new read, handles disconnection
func (uA *UserArr) handleSuperuserConnection(c net.Conn, userName string) {
	for {
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		temp := strings.TrimSpace(string(netData))
		if temp == "STOP" {
			discMess := "__User " + userName + " disconnected__"
			fmt.Println(discMess)
			uA.sendAllElse(c, discMess)
			uA.deleteUser(c)
			break
		}

		message := "User " + userName + ": " + temp

		fmt.Println(message)
		uA.sendAllElse(c, message)

	}
	c.Close()
}

// Generates new read, handles disconnection, sends the message to all other connections
func (uA *UserArr) handleClient(c net.Conn, userName string, itemList []string) {
	fmt.Fprintln(c, "Welcome! List of items:", itemList)

	for {
		netData, err := bufio.NewReader(c).ReadString('\n')
		if err != nil {
			fmt.Println(err)
			return
		}

		temp := strings.TrimSpace(string(netData))
		if temp == "STOP" {
			discMess := "__User " + userName + " disconnected__"
			fmt.Println(discMess)
			uA.sendAllElse(c, discMess)
			uA.deleteUser(c)
			break
		}

		message := "User " + userName + ": " + temp

		fmt.Println(message)
		uA.sendAllElse(c, message)

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
