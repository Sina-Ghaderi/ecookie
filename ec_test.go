package ecookie

import (
	"encoding/json"
	"testing"
)

type test struct {
	Foo string
	Bar string
}

const pattr string = "ecookie: --- %v --"

const (
	foo = "foo string"
	bar = "bar string"
)

var key = []byte{
	0x11, 0x12, 0x13, 0x14,
	0x11, 0x12, 0x13, 0x14,
	0x11, 0x12, 0x13, 0x14,
	0x11, 0x12, 0x13, 0x14,
}

func TestEcookie(t *testing.T) {
	enc, err := NewEncryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	tx := &test{Foo: foo, Bar: bar}
	bx := new(test)
	bt, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}

	ct, err := enc.Encrypt(bt)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf(pattr, string(ct))

	dec, err := NewDecryptor(key)
	if err != nil {
		t.Fatal(err)
	}

	pt, err := dec.Decrypt(ct)
	if err != nil {
		t.Fatal(err)
	}

	if err := json.Unmarshal(pt, bx); err != nil {
		t.Fatal(err)
	}

	if !(*tx == *bx) {
		t.Error("error: tx != bx.. test failed")
	}
}
