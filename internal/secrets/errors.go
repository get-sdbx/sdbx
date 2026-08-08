package secrets

import (
	"errors"
	"fmt"
)

// SecretNotConfiguredError indicates a secret file is not properly configured
type SecretNotConfiguredError struct {
	Filename string
}

func (e *SecretNotConfiguredError) Error() string {
	return fmt.Sprintf("secret not configured: %s (file is empty or contains placeholder)", e.Filename)
}

// IsSecretNotConfigured checks if error is SecretNotConfiguredError
func IsSecretNotConfigured(err error) bool {
	var target *SecretNotConfiguredError
	return errors.As(err, &target)
}
