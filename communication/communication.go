package communication

// BroadcastMessage is a wrapper for a message broadcasted by a
// party in the protocol
type BroadcastMessage struct {
	Payload  []byte `msg:"payload"`
	SenderID int    `msg:"sender_id"`
}

// RoundMessages is a wrapper for all the messages send in a round
type RoundMessages struct {
	Messages []BroadcastMessage `msg:"messages"`
	Round    int                `msg:"round"`
}

// BroadcastChannel is a channel used by a party to perform
// send and receive operations in the execution of a protocol
type BroadcastChannel interface {
	Send(msg []byte)
	ReceiveRound() (int, []BroadcastMessage)
}

// ProtocolParty is a partipant in a communication protocol
type ProtocolParty interface {
	GetID() int
	GetBroadcastChannel() BroadcastChannel
	StartProtocol() error
}

// ComplaintResponseMessageWrapper is raw type of ComplaintResponseMessage used for msgp
type ComplaintResponseMessageWrapper struct {
	ComplaintShares []struct {
		Index       int
		IndexScalar [32]byte
		S           [32]byte
		R           [32]byte
	}
}
