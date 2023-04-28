package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
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

	arr := make([]string, 0)
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("Client Name: ")
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
	uName := arr[0]
	uDenom := arr[1]

	fmt.Fprintln(c, "Username:"+uName+":"+uDenom)

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
		}
		fmt.Println(messTrimmed)
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
				fmt.Println("TCP client exiting...")
				os.Exit(0)
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
