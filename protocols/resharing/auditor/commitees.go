package auditor

import "github.com/shaih/go-yosovss/protocols/resharing/common"

// Committees contains the list of committee members for a round of
// resharing
// Contrary to basic and futurebroadcast protocols, the next committee
// is included there
type Committees struct {
	Hold []int // previous holding committee = dealers
	Ver  []int // verification committee
	Res  []int // resolution committee = future broadcast
	Wit  []int // witness committee
	Aud  []int // auditing committee
	Next []int // next holding committee
}

// CommitteeIndices is a struct that contains for a participant in the protocol their index in each of the committees
// for a round of resharing. If an index is -1, that means that the party is not a part of the committee for the round.
// Otherwise, indices range from 1 to n. Note that these indices represent a party's index with respect to the
// committee specifically, not the id of the party with respect to the entire protocol.
type CommitteeIndices struct {
	Hold int
	Ver  int
	Res  int
	Wit  int
	Aud  int
	Next int
}

// Indices return the committees indices of the committees for a given party id
func (c *Committees) Indices(id int) CommitteeIndices {
	return CommitteeIndices{
		Hold: common.IntIndexOf(c.Hold, id),
		Ver:  common.IntIndexOf(c.Ver, id),
		Res:  common.IntIndexOf(c.Res, id),
		Wit:  common.IntIndexOf(c.Wit, id),
		Aud:  common.IntIndexOf(c.Aud, id),
		Next: common.IntIndexOf(c.Next, id),
	}
}
