package ima_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	"testing"

	"pault.ag/go/ima"
)

func TestSign(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	isok(t, err)

	hash := sha256.New()
	hash.Write([]byte("Totally real ELF no tricks"))
	digest := hash.Sum(nil)

	sigBytes, err := ima.Sign(key, rand.Reader, digest, crypto.SHA256)
	isok(t, err)

	sig, err := ima.Parse(sigBytes)
	isok(t, err)

	assert(t, len(sig.Signature) == 128)

	isok(t, sig.Verify(key.PublicKey, digest, crypto.SHA256))
	isok(t, rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest, sig.Signature))
}
