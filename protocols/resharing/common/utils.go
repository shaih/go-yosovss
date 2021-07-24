package common

// IntIndexOf returns the first position in a slice that has a value,
// or -1 if the slice does not contain the value.
func IntIndexOf(list []int, val int) int {
	for i, v := range list {
		if v == val {
			return i
		}
	}
	return -1
}
