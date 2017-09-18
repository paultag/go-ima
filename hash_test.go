package ima_test

import (
	"crypto"
	"testing"

	"pault.ag/go/ima"
)

func TestLookup(t *testing.T) {
	hash, err := ima.HashFunctions.IMAToGo(ima.SHA1.Id)
	isok(t, err)
	assert(t, hash != nil)
	assert(t, *hash == crypto.SHA1)

	hash, err = ima.HashFunctions.IMAToGo(ima.SHA512.Id)
	isok(t, err)
	assert(t, hash != nil)
	assert(t, *hash == crypto.SHA512)
}

func TestIMALookup(t *testing.T) {
	hash, err := ima.HashFunctions.GoToIMA(crypto.SHA1)
	isok(t, err)
	assert(t, hash != nil)
	assert(t, *hash == ima.SHA1)

	hash, err = ima.HashFunctions.GoToIMA(crypto.SHA512)
	isok(t, err)
	assert(t, hash != nil)
	assert(t, *hash == ima.SHA512)
}
