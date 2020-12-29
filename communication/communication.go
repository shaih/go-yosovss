package communication

// Participant is a party in the protocol
type Participant struct {
	ID             int
	SendChannel    chan []byte
	ReceiveChannel chan []byte
}

// Orchestrator collects messages from participants
// and broadcasts the messages at the end of each round
type Orchestrator struct {
	SendChannels    []chan []byte
	ReceiveChannels []chan []byte
	MessageQueue    [][]byte
}

// Init creates n participants and creates channels to the orchestrator
func Init(n int) (*[]Participant, *Orchestrator) {
	return nil, nil
}

// SendMessage sends a message from a participant to the orchestrator
func (p *Participant) SendMessage(message []byte) error {
	return nil
}

// ReceiveMessages gets all of the messages broadcasted in a round of the protocol
// from the orchestrator
func (p *Participant) ReceiveMessages() ([]byte, error) {
	return nil, nil
}

// Start initializes a go routine for the orchestrator to start processing messages
// from participants and broadcasts messages at the end of each round
func (o *Orchestrator) Start() error {
	return nil
}

// sendMessages has the orchestrator push all of the messages received in a round
// through to all of the participants
func (o *Orchestrator) sendMessages() error {
	return nil
}
