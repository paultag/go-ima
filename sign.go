package ima

import (
	"fmt"
	"io"

	"crypto"
	"crypto/rsa"
)

func Sign(signer crypto.Signer, rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	imaHash, err := HashFunctions.ToHash(opts.HashFunc())
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

func (s Signature) Verify(pub crypto.PublicKey, digest []byte, hash crypto.Hash) error {
	switch pub.(type) {
	case rsa.PublicKey:
		pubRSA := pub.(rsa.PublicKey)
		return rsa.VerifyPKCS1v15(&pubRSA, hash, digest, s.Signature)
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), hash, digest, s.Signature)
	default:
		return fmt.Errorf("ima: PublicKey format not understood")
	}
}
