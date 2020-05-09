package dialogue

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/scrypt"
)

const SaltLength = 12

func Encrypt(pt, passwd []byte, r io.Reader) ([]byte, error) {
	nonce := make([]byte, SaltLength)
	if _, err := r.Read(nonce); err != nil {
		return nil, err
	}

	dk, err := scrypt.Key(passwd, nonce, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ct := aesgcm.Seal(nil, nonce, pt, nil)

	ct = append(ct, nonce...)

	return ct, nil
}

func Decrypt(ct, passwd []byte) ([]byte, error) {
	cl := len(ct) - SaltLength
	salt := ct[cl:]
	str := hex.EncodeToString(salt)

	nonce, err := hex.DecodeString(str)

	dk, err := scrypt.Key(passwd, nonce, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	pt, err := aesgcm.Open(nil, nonce, ct[:cl], nil)
	if err != nil {
		return nil, err
	}

	return pt, nil
}
