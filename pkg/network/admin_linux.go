package network

import (
	"fmt"
	"os"
)

func CheckAdminPrivileges() error {
	if os.Getuid() != 0 {
		return fmt.Errorf("root privileges required (run with sudo)")
	}
	return nil
}
