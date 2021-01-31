package communication

// BroadcastMessage is a wrapper for a message broadcasted by a
// party in the protocol
type BroadcastMessage struct {
	_struct  struct{} `codec:",omitempty,omitemptyarray"`
	Payload  []byte   `codec:"payload"`
	SenderID int      `codec:"snd_id"`
}

// RoundMessages is a wrapper for all the messages send in a round
type RoundMessages struct {
	_struct  struct{}           `codec:",omitempty,omitemptyarray"`
	Messages []BroadcastMessage `codec:"msgs"`
	Round    int                `codec:"rnd"`
}

// BroadcastChannel is a channel used by a party to perform
// send and receive operations in the execution of a protocol
type BroadcastChannel interface {
	Send(msg []byte)
	ReceiveRound() (int, []BroadcastMessage)
}
