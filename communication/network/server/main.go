package server

import (
	"fmt"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s [port] [num clients]\n", os.Args[0])
		os.Exit(1)
	}
	port := os.Args[1]

	numClients, err := strconv.Atoi(os.Args[2])
	if err != nil || numClients < 0 {
		fmt.Printf("invalid number of clients")
		os.Exit(1)
	}

	ns := NewNetworkServer()

	ns.ListenTCP(port, numClients)
}