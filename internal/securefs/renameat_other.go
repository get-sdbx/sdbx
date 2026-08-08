//go:build !darwin && !linux

package securefs

import (
	"fmt"
	"os"
)

// RenameBaseAt is unsupported where directory-descriptor rename is
// unavailable. SDBX release targets use the darwin/linux implementation.
func RenameBaseAt(
	_ *os.Root,
	_ string,
	_ *os.Root,
	_ string,
) error {
	return fmt.Errorf("pinned cross-directory rename is unsupported on this platform")
}
