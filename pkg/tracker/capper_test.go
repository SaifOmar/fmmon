package tracker

import "testing"

func TestParseCapSize(t *testing.T) {
	tests := []struct {
		input string
		want  int64
	}{
		{"", 0},
		{"0", 0},
		{"100", 100},
		{"100B", 100},
		{"1KB", 1024},
		{"2KB", 2048},
		{"1MB", 1024 * 1024},
		{"5MB", 5 * 1024 * 1024},
		{"1GB", 1024 * 1024 * 1024},
		{"1.5KB", 1536},
		{"0.5MB", 512 * 1024},
		{" 100KB ", 102400},
		{"100kb", 102400},
		{"100Kb", 102400},
	}
	for _, tt := range tests {
		got, err := ParseCapSize(tt.input)
		if err != nil {
			t.Errorf("ParseCapSize(%q) unexpected error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Errorf("ParseCapSize(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

func TestParseCapSize_Error(t *testing.T) {
	tests := []string{"abc", "10XB", "1YB"}
	for _, input := range tests {
		_, err := ParseCapSize(input)
		if err == nil {
			t.Errorf("ParseCapSize(%q) expected error, got nil", input)
		}
	}
}
