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

	// requires a ip:port
	CONNECT := arguments[1]
	c, err := net.Dial("tcp", CONNECT)
	if err != nil {
		fmt.Println(err)
		return
	}

	// new array to hold auctioneer name, auctioneer denomination
	arr := make([]string, 0)
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("Auctioneer Name: ")
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

	var numThings int

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
	for i := 0; i < numThings; i++ {
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
					numThings = n
					arrIndiv = append(arrIndiv, text)
					break
				}
			}
			fmt.Println("Try Again!")
		}

		// takes item, description, price, and makes it a string broken up by the @ symbol
		formatIndiv := strings.Join(arrIndiv, "@")

		// appends the above string to the list of things being auctioned
		arrT = append(arrT, formatIndiv)

		fmt.Print("\n\n\n")
	}

	formatarrT := strings.Join(arrT, "~")

	fmt.Fprint(c, "AUCTIONEER:"+arr[0]+":"+arr[1]+":"+formatarrT+"\n")

	go auctioneerSend(c)

	// reads from server, prints server send
	for {
		message, _ := bufio.NewReader(c).ReadString('\n')
		mess := strings.TrimSpace(string(message))
		if mess == "An auction has already begun!" {
			break
		} else if mess == "Auction Terminated" {
			break
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
			fmt.Print("\n")
			// Scans a line from Stdin(Console)
			scanner.Scan()
			// Holds the string that scanned
			text := scanner.Text()

			// Client wants to exit the auction
			message := strings.TrimSpace(string(text))
			if message == "STOP" {
				fmt.Println("TCP client exiting...")
				os.Exit(0)
			} else if message == "NEXT" {
				mess = message
				break
			}
			fmt.Println("Try Again!")
		}

		// only sends to server if the client input a number
		fmt.Fprintln(c, fmt.Sprint(mess))
	}
}
