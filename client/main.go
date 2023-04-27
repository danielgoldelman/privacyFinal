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

	for {
		message, _ := bufio.NewReader(c).ReadString('\n')
		fmt.Print(message)
		if strings.TrimSpace(string(message)) == "Please wait for the auction to begin!" {
			os.Exit(0)
		} else {
			break
		}
	}

	// starts separate thread for this for loop

	// takes in user input, sends to server
	go runClient(c)

	// reads from server, prints server send
	for {
		message, _ := bufio.NewReader(c).ReadString('\n')
		if strings.TrimSpace(string(message)) == "Please wait for the auction to begin!" {
			os.Exit(0)
		}
		fmt.Print(message)
	}
}

func runClient(c net.Conn) {
	for {
		var num int
		scanner := bufio.NewScanner(os.Stdin)
		for {
			fmt.Print("\n")
			// Scans a line from Stdin(Console)
			scanner.Scan()
			// Holds the string that scanned
			text := scanner.Text()

			if strings.TrimSpace(string(text)) == "STOP" {
				fmt.Println("TCP client exiting...")
				os.Exit(0)
			}

			if len(text) != 0 {
				if n, e := strconv.Atoi(text); e == nil {
					num = n
					break
				}
			}
			fmt.Println("Try Again!")
		}
		fmt.Fprintln(c, fmt.Sprint(num))
	}
}
