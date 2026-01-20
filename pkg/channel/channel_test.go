package channel

import (
	"testing"
)

func TestSelectVersion(t *testing.T) {
	tests := []struct {
		ours   []uint16
		theirs []uint16
		want   uint16
	}{
		{[]uint16{4, 5}, []uint16{3, 4, 5}, 5},
		{[]uint16{4, 5}, []uint16{3, 4}, 4},
		{[]uint16{4, 5}, []uint16{3}, 0},
		{[]uint16{4, 5}, []uint16{4, 5}, 5},
		{[]uint16{3, 4, 5}, []uint16{5}, 5},
		{[]uint16{}, []uint16{4, 5}, 0},
		{[]uint16{4}, []uint16{}, 0},
	}

	for _, tt := range tests {
		got := selectVersion(tt.ours, tt.theirs)
		if got != tt.want {
			t.Errorf("selectVersion(%v, %v) = %d, want %d", tt.ours, tt.theirs, got, tt.want)
		}
	}
}
