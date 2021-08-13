package auditor

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRangeSlice(t *testing.T) {
	assert := assert.New(t)

	assert.Equal([]int{}, rangeSlice(10, 0))
	assert.Equal([]int{0, 1, 2}, rangeSlice(0, 3))
	assert.Equal([]int{10}, rangeSlice(10, 1))
	assert.Equal([]int{2, 3, 4, 5, 6}, rangeSlice(2, 5))
}

func TestSeqCommittees(t *testing.T) {
	assert := assert.New(t)

	assert.Equal(
		Committees{
			Hold: []int{0, 1, 2},
			Ver:  []int{3, 4, 5},
			Res:  []int{6, 7, 8},
			Wit:  []int{9, 10, 11},
			Aud:  []int{12, 13, 14},
			Next: []int{15, 16, 17},
		},
		seqCommittees(3),
	)
}
