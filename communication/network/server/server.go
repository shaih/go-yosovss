package server

import (
	"bytes"
	"fmt"
	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/communication"
	"github.com/shaih/go-yosovss/communication/network"
	"io"
	"net"
)

// NetworkServer is the server for coordinating the broadcasts of clients
type NetworkServer struct {
	Clients  map[int]string
	RoundMsgs map[int]communication.BroadcastMessage
	Round     int
}

// NetNetworkServer returns a new instance of a server
func NewNetworkServer() NetworkServer {
	return NetworkServer{
		Clients:  make(map[int]string),
		RoundMsgs: make(map[int]communication.BroadcastMessage),
		Round:     0,
	}
}

func (ns NetworkServer) ListenTCP(port string, numClients int) {
	l, err := net.Listen("tcp4", ":" + port)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	for {
		for i := 0; i < numClients; i++ {
			conn, err := l.Accept()
			if err != nil {
				fmt.Println(err)
				return
			}
			go ns.handleConnection(conn)
		}

		err := ns.Broadcast()
		if err != nil {
			fmt.Println(err)
			return
		}
	}
}

func (ns NetworkServer) handleConnection(conn net.Conn) {
	for {
		var buf bytes.Buffer
		_, err := io.Copy(&buf, conn)
		if err != nil {
			fmt.Printf("unable to read client message: %v", err)
			return
		}

		var cliMsg network.ClientMessage
		err = msgpack.Decode(buf.Bytes(), &cliMsg)
		if err != nil {
			fmt.Printf("unable to decode client message: %v", err)
			return
		}

		ns.Clients[cliMsg.ID] = conn.RemoteAddr().String()
		ns.RoundMsgs[cliMsg.ID] = cliMsg.Msg
	}
}

// Broadcast sends to all parties the messages in the round
func (ns NetworkServer) Broadcast() error {
	var msgs []communication.BroadcastMessage
	for i := 0; i < len(ns.Clients); i++ {
		msgs = append(msgs, ns.RoundMsgs[i])
	}
	roundMsgs := communication.RoundMessages{
		Messages: msgs,
		Round:    ns.Round,
	}

	for _, connect := range ns.Clients {
		c, err := net.Dial("tcp", connect)
		if err != nil {
			return fmt.Errorf("unable to broadcast to %s: %v", connect, err)
		}
		_, err = c.Write(msgpack.Encode(roundMsgs))
		if err != nil {
			return fmt.Errorf("unable to write round messages to %s: %v", connect, err)
		}
		c.Close()
	}

	return nil
}