package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

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

	// for each new user (connection)
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
		fmt.Println("New User: ", temp)

		go uA.handleConnection(c, temp)
		uA.addCtoCL(c, temp)
	}
}

type UserArr struct {
	cl []net.Conn
}

// Generates new read, handles disconnection, sends the message to all other connections
func (uA *UserArr) handleConnection(c net.Conn, userName string) {
	if len(uA.cl) == 1 {
		fmt.Fprintln(c, "You are the first user")
	} else {
		fmt.Fprintln(c, uA.others()+" other users already connected")
	}

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

func (uA *UserArr) others() string {
	return fmt.Sprint(len(uA.cl) - 1)
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
