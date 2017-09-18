package ima_test

import (
	"crypto"
	"testing"

	"pault.ag/go/ima"
)

func TestLookup(t *testing.T) {
	hash, err := ima.HashFunctions.ToCrypto(ima.SHA1.Id)
	isok(t, err)
	assert(t, hash != nil)
	assert(t, *hash == crypto.SHA1)

	hash, err = ima.HashFunctions.ToCrypto(ima.SHA512.Id)
	isok(t, err)
	assert(t, hash != nil)
	assert(t, *hash == crypto.SHA512)
}

func TestIMALookup(t *testing.T) {
	hash, err := ima.HashFunctions.ToHash(crypto.SHA1)
	isok(t, err)
	assert(t, hash != nil)
	assert(t, *hash == ima.SHA1)

	hash, err = ima.HashFunctions.ToHash(crypto.SHA512)
	isok(t, err)
	assert(t, hash != nil)
	assert(t, *hash == ima.SHA512)
}
