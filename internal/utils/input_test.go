package utils

import (
	"bytes"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetUserInput_File(t *testing.T) {
	in := []byte("foo")
	f := writeToTempFile(t, in)

	b, err := GetUserInput(f.Name(), nil)

	assert.NoError(t, err)
	assert.Equal(t, in, b)
}

func TestGetUserInput_BadFile(t *testing.T) {
	b, err := GetUserInput("notafile", nil)

	assert.Nil(t, b)
	assert.ErrorContains(t, err, "could not open file")
}

func TestGetUserInput_Stdin(t *testing.T) {
	in := []byte("bar")

	b, err := GetUserInput("-", bytes.NewReader(in))

	assert.NoError(t, err)
	assert.Equal(t, in, b)
}

func TestGetUserInput_NoContent(t *testing.T) {
	in := new([]byte)

	b, err := GetUserInput("-", bytes.NewReader(*in))

	assert.ErrorContains(t, err, "no input given")
	assert.Nil(t, b)
}

func writeToTempFile(t *testing.T, b []byte) *os.File {
	t.Helper()

	f, err := os.CreateTemp("", "tmpfile-")
	require.NoError(t, err)

	n, err := f.Write(b)
	require.Equal(t, len(b), n)
	require.NoError(t, err)

	return f
}
