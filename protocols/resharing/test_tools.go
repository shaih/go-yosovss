package resharing

const (
	numRounds     = 3 // number of rounds of messaging required for the protocol
	numCommittees = 4 // number of committees
)

func rangeSlice(start, length int) []int {
	s := make([]int, length)
	for i := 0; i < length; i++ {
		s[i] = start + i
	}
	return s
}

// seqCommittees generates committees of n*numCommittees parties
// where parties 0,...,n-1 are first holding committee
// n,...,2n-1 are verification committee
// and so on
func seqCommittees(n int) Committees {
	return Committees{
		Hold: rangeSlice(0, n),
		Ver:  rangeSlice(n, n),
		Res:  rangeSlice(2*n, n),
		Next: rangeSlice(3*n, n),
	}
}

// sameCommittees generates committees of n parties
// where parties 0,...,n-1 are in all the committees
func sameCommittees(n int) Committees {
	return Committees{
		Hold: rangeSlice(0, n),
		Ver:  rangeSlice(0, n),
		Res:  rangeSlice(0, n),
		Next: rangeSlice(0, n),
	}
}
