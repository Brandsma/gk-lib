package util


import (
	"time"
)

func retry(attempts int, sleep time.Duration, fn func(var *interface{}) error) error {
	if err := fn(var); err != nil {
		if s, ok := err.(stop); ok {
			// Return the original error for later checking
			return s.error
		}

		if attempts--; attempts > 0 {
			time.Sleep(sleep)
			return retry(attempts, 2*sleep, fn(var))
		}

		return err

	}
	return nil
}

type stop struct {
	error
}
