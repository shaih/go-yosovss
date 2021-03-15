package client

import (
	"bytes"
	"fmt"
	"github.com/algorand/go-algorand-sdk/encoding/msgpack"
	"github.com/shaih/go-yosovss/communication"
	"github.com/shaih/go-yosovss/communication/network"
	"io"
	"net"
)

// NetworkBroadcastChannel is the channel a party participating in the
// protocol uses to communicate with the orchestrator server over TCP
type NetworkBroadcastChannel struct {
	ID             int
	SendChannel    chan communication.BroadcastMessage
	ReceiveChannel chan communication.RoundMessages
}

// SendTCP sends the broadcast message to the server over TCP
func SendTCP(
	id int,
	connect string,
	sendChan chan communication.BroadcastMessage,
) {
	bcastMsg := <-sendChan
	conn, err := net.Dial("tcp", connect)
	if err != nil {
		fmt.Println(err)
		return
	}

	cliMsg := network.ClientMessage{
		ID: id,
		Msg: bcastMsg,
	}

	_, err = conn.Write(msgpack.Encode(cliMsg))
	if err != nil {
		fmt.Println(err)
		return
	}

	conn.Close()
}

// ListenTCP listens for a TCP connection from the server to collect the next round's message
func ListenTCP(
	port string,
	recChan chan communication.RoundMessages,
) {
	l, err := net.Listen("tcp4", ":" + port)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}

		var buf bytes.Buffer
		_, err = io.Copy(&buf, conn)
		if err != nil {
			fmt.Println(err)
			return
		}

		var roundMsgs communication.RoundMessages
		err = msgpack.Decode(buf.Bytes(), &roundMsgs)
		if err != nil {
			fmt.Printf("unable to decode round messages: %v", err)
			return
		}

		recChan <- roundMsgs
	}

}

// NewNetworkBroadcastChannel creates a new party to connect with an orchestrator server
func NewNetworkBroadcastChannel(id int, connect string, port string) NetworkBroadcastChannel {

	sendChan := make(chan communication.BroadcastMessage, 1)
	recChan := make(chan communication.RoundMessages, 1)

	go SendTCP(id, connect, sendChan)
	go ListenTCP(port, recChan)

	return NetworkBroadcastChannel{
		ID:             id,
		SendChannel:    sendChan,
		ReceiveChannel: recChan,
	}
}

// Send allows for a party to give the orchestrator a message to be broadcasted
// during the round
func (nbc NetworkBroadcastChannel) Send(msg []byte) {
	bcastMsg := communication.BroadcastMessage{
		Payload:  msg,
		SenderID: nbc.ID,
	}

	nbc.SendChannel <- bcastMsg
}

// ReceiveRound is called by a party to get the round number and messages broadcasted by all parties
// in the given round
func (nbc NetworkBroadcastChannel) ReceiveRound() (int, []communication.BroadcastMessage) {
	roundMsgs := <-nbc.ReceiveChannel
	return roundMsgs.Round, []communication.BroadcastMessage(roundMsgs.Messages)
}