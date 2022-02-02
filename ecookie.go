package ecookie

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"

	"github.com/sina-ghaderi/rabbitio"
	"golang.org/x/crypto/blake2b"
)

var (
	ErrAUTHCOK = errors.New("ecookie: cookie is corrupted")
	ErrENDDATA = errors.New("ecookie: cookie length is too short")

	ErrBadKlen = errors.New("ecookie: key must be 16 byte len")
)

const (
	lenhashfnc = 32
	lenkrabbit = 16
	lenivahash = lenhashfnc + lenivforkt
	lenivforkt = 8
)

type Encryptor struct {
	key []byte
}

type Decryptor struct {
	key []byte
}

func NewEncryptor(key []byte) (*Encryptor, error) {
	if len(key) != lenkrabbit {
		return nil, ErrBadKlen
	}
	copyKey := make([]byte, lenkrabbit)
	copy(copyKey, key)
	return &Encryptor{key: copyKey}, nil
}

func NewDecryptor(key []byte) (*Decryptor, error) {
	if len(key) != lenkrabbit {
		return nil, ErrBadKlen
	}
	copyKey := make([]byte, lenkrabbit)
	copy(copyKey, key)
	return &Decryptor{key: copyKey}, nil
}

func randomIVGen() ([]byte, error) {
	iv := make([]byte, lenivforkt)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	return iv, nil
}

func (h *Encryptor) Encrypt(src []byte) ([]byte, error) {
	ivx, err := randomIVGen()
	if err != nil {
		return nil, err
	}

	cip, _ := rabbitio.NewCipher(h.key, ivx)
	dst := make([]byte, len(src))
	cip.XORKeyStream(dst, src)
	hash, err := blake2bHash(multiReader(h.key, ivx, dst))
	if err != nil {
		return nil, err
	}

	buff := new(bytes.Buffer)
	_, err = io.Copy(hex.NewEncoder(buff), multiReader(hash, ivx, dst))
	return buff.Bytes(), err
}

func multiReader(vs ...[]byte) io.Reader {

	var rds []io.Reader
	for _, x := range vs {
		r := bytes.NewReader(x)
		rds = append(rds, r)
	}

	return io.MultiReader(rds...)
}

func blake2bHash(r io.Reader) ([]byte, error) {
	hasher, _ := blake2b.New256(nil)
	if _, err := io.Copy(hasher, r); err != nil {
		return nil, err
	}
	return hasher.Sum(nil), nil
}

func (h *Decryptor) Decrypt(raw []byte) ([]byte, error) {
	bf := new(bytes.Buffer)
	if _, err := io.Copy(bf,
		hex.NewDecoder(bytes.NewReader(raw))); err != nil {
		return nil, err
	}

	if bf.Len() < lenivahash {
		return nil, ErrENDDATA
	}

	u := bf.Bytes()
	cl, err := blake2bHash(multiReader(h.key, u[lenhashfnc:]))
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(cl, u[:lenhashfnc]) {
		return nil, ErrAUTHCOK
	}

	cip, _ := rabbitio.NewCipher(h.key, u[lenhashfnc:lenivahash])
	pln := make([]byte, bf.Len()-lenivahash)
	cip.XORKeyStream(pln, u[lenivahash:])
	return pln, err
}
