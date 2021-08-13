package auditor

const (
	numRounds     = 5 // number of rounds of messaging required for the protocol
	numCommittees = 6 // number of committees
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
		Wit:  rangeSlice(3*n, n),
		Aud:  rangeSlice(4*n, n),
		Next: rangeSlice(5*n, n),
	}
}