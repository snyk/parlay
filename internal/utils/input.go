package utils

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// GetUserInput will open and read from the given filename. If filename is
// "-", it will read from the given file instead.
func GetUserInput(filename string, file io.Reader) (b []byte, err error) {
	if filename != "-" {
		file, err = os.Open(filename)
		if err != nil {
			return nil, fmt.Errorf("could not open file: %w", err)
		}
	}

	b, err = io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("could not read file: %w", err)
	}

	if len(b) == 0 {
		return nil, errors.New("no input given")
	}

	return b, nil
}
