package ima

import (
	"crypto"
	"io"
)

func Sign(signer crypto.Signer, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	imaHash, err := HashFunctions.GoToIMA(opts.HashFunc())
	if err != nil {
		return nil, err
	}

	keyId, err := PublicKeyId(signer.Public())
	if err != nil {
		return nil, err
	}

	ret := Signature{Header: SignatureHeader{
		Magic:         0x03,
		Version:       0x02,
		HashAlgorithm: imaHash.Id,
		KeyID:         keyId,
	}}

	signature, err := signer.Sign(rand, digest, opts)
	if err != nil {
		return nil, err
	}

	ret.Header.SignatureLength = uint16(len(signature))
	ret.Signature = signature

	return Serialize(ret)
}
