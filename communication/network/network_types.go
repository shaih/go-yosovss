package network

import "github.com/shaih/go-yosovss/communication"

// ClientMessage is a wrapper for client messages to the server that specify the
// sender's ID
type ClientMessage struct {
	ID int
	Msg communication.BroadcastMessage
}