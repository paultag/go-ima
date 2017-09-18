package ima

import (
	"crypto"
	"io"
)

func Sign(signer crypto.Signer, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	ret := Signature{Header: SignatureHeader{}}

	signer.Sign(rand, digest, opts)

	return Serialize(ret)
}
