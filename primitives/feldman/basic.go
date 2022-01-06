package feldman

import "github.com/shaih/go-yosovss/primitives/curve25519"

// GCommitment represents a basic Feldman commitment
// Commitment of x is x * G, where G is the main base for curve25519
type GCommitment = curve25519.PointXY
