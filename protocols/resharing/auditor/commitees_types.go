package auditor

import "github.com/shaih/go-yosovss/protocols/resharing/common"

// Committees contains the list of committee members for a round of
// resharing
type Committees struct {
	Hold []int
	Ver  []int
	Res  []int
	Wit  []int
}

// CommitteeIndices is a struct that contains for a participant in the protocol their index in each of the committees
// for a round of resharing. If an index is -1, that means that the party is not a part of the committee for the round.
// Otherwise, indices range from 0 to n-1. Note that these indices represent a party's index with respect to the
// committee specifically, not the id of the party with respect to the entire protocol.
type CommitteeIndices struct {
	Hold int
	Ver  int
	Res  int
	Wit  int
}

// Indices return the committees indices of the committes for a given party id
func (c *Committees) Indices(id int) CommitteeIndices {
	return CommitteeIndices{
		Hold: common.IntIndexOf(c.Hold, id),
		Ver:  common.IntIndexOf(c.Ver, id),
		Res:  common.IntIndexOf(c.Res, id),
		Wit:  common.IntIndexOf(c.Wit, id),
	}
}
