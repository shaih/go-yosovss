package client

import (
	"fmt"
	"log"
	"os"
	"strconv"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s [id] [server host:port] [port]\n", os.Args[0])
		os.Exit(1)
	}

	id, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Printf("id not a integer")
		os.Exit(1)
	}
	connect := os.Args[2]
	port := os.Args[3]

	nbc := NewNetworkBroadcastChannel(id, connect, port)

	for i := 0; i < 5; i++ {
		msg := fmt.Sprintf("message for round %d from party %d", i, nbc.ID)
		nbc.Send([]byte(msg))

		round, roundMsgs := nbc.ReceiveRound()

		var roundMsgsString []string
		for _, roundMsgString := range roundMsgs {
			roundMsgsString = append(roundMsgsString, string(roundMsgString.Payload))
		}

		log.Printf("party %d received messages: %v for round %d\n", nbc.ID, roundMsgsString, round)
	}
}