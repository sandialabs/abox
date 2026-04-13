// Package natsort provides natural (numeric-aware) string comparison.
package natsort

import "strconv"

// extractNumber parses the leading numeric segment of s starting at index i.
// It returns the parsed integer value and the index one past the last digit.
func extractNumber(s string, i int) (int, int) {
	j := i
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	n, _ := strconv.Atoi(s[i:j])
	return n, j
}

// Less reports whether a < b using natural sort order, where numeric
// segments are compared by value so that "item-2" < "item-10".
func Less(a, b string) bool {
	for {
		if a == b {
			return false
		}
		if a == "" {
			return true
		}
		if b == "" {
			return false
		}

		aDigit := a[0] >= '0' && a[0] <= '9'
		bDigit := b[0] >= '0' && b[0] <= '9'

		switch {
		case aDigit && bDigit:
			an, aj := extractNumber(a, 0)
			bn, bj := extractNumber(b, 0)
			if an != bn {
				return an < bn
			}
			a = a[aj:]
			b = b[bj:]
		case aDigit != bDigit:
			return a[0] < b[0]
		default:
			if a[0] != b[0] {
				return a[0] < b[0]
			}
			a = a[1:]
			b = b[1:]
		}
	}
}
