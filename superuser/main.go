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
			if len(text) != 0 {
				if n, e := strconv.Atoi(text); e == nil {
					numThings = n
					arrIndiv = append(arrIndiv, text)
					break
				}
			}
			fmt.Println("Try Again!")
		}

		formatIndiv := strings.Join(arrIndiv, "@")

		arrT = append(arrT, formatIndiv)

		fmt.Print("\n\n\n")
	}

	fmt.Fprint(c, "SUPERUSER:"+arr[0]+":"+arr[1]+":"+strings.Join(arrT, "~")+"\n")

	// reads from server, prints server send
	for {
		message, _ := bufio.NewReader(c).ReadString('\n')
		fmt.Print(message)
	}
}
