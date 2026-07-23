package network

import (
	"fmt"
	"os"
)

func CheckAdminPrivileges() error {
	_, err := os.Open(`\\.\PHYSICALDRIVE0`)
	if err != nil {
		return fmt.Errorf("administrator privileges required (run as administrator): %w", err)
	}
	return nil
}
