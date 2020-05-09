package dialogue_test

import (
	"strings"
	"testing"

	"github.com/BradLugo/dialogue"
	"github.com/stretchr/testify/assert"
)

var tests = []struct {
	plaintext  string
	password   string
	ciphertext string
}{
	{`Simple`, `test`, "ad\xa2o\x03`/\xe0ӷ\x82\xb2pf\x1eSU\x14\x0e\xa5\xb3\xadTest salt!!!"},
}

func TestEncrypt(t *testing.T) {
	r := strings.NewReader("Test salt!!!")
	for _, c := range tests {
		t.Run(c.plaintext, func(t *testing.T) {
			s, err := dialogue.Encrypt([]byte(c.plaintext), []byte(c.password), r)
			assert.NoError(t, err)
			assert.Equal(t, c.ciphertext, string(s))
		})
	}
}

func TestDecrypt(t *testing.T) {
	for _, c := range tests {
		t.Run(c.plaintext, func(t *testing.T) {
			s, err := dialogue.Decrypt([]byte(c.ciphertext), []byte(c.password))
			assert.NoError(t, err)
			assert.Equal(t, c.plaintext, string(s))
		})
	}
}
