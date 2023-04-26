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
		fmt.Println("Please provide host:port.")
		return
	}

	CONNECT := arguments[1]
	c, err := net.Dial("tcp", CONNECT)
	if err != nil {
		fmt.Println(err)
		return
	}

	// take in username from user input
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Username: ")
	uName, _ := reader.ReadString('\n')
	// send username to server
	fmt.Fprintf(c, uName+"\n")

	// starts separate thread for this for loop

	// takes in user input, sends to server
	go func() {
		for {
			reader := bufio.NewReader(os.Stdin)
			text, _ := reader.ReadString('\n')
			fmt.Fprintf(c, text+"\n")
			if strings.TrimSpace(string(text)) == "STOP" {
				fmt.Println("TCP client exiting...")
				os.Exit(0)
			}
		}
	}()

	// reads from server, prints server send
	for {
		message, _ := bufio.NewReader(c).ReadString('\n')
		fmt.Print(message)
	}
}
