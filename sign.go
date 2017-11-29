// Copyright 2017 Paul Tagliamonte <paultag@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ima

import (
	"fmt"
	"io"

	"crypto"
	"crypto/rsa"
)

// Given a crypto.Signer, a RNG source (to be used during the underlying
// signer.Sign call), a digest, and a crypto.SignerOpts, sign the digest
// and serialize the Signature as an IMA EVM v2.0 signature.
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

type VerifyOptions struct {
	Digest []byte
	Hash   crypto.Hash

	Keys KeyPool
}

var (
	UnknownSigner error = fmt.Errorf("ima: unknown signature keyid")
)

func (s Signature) Verify(opts VerifyOptions) (crypto.PublicKey, error) {
	candidates := opts.Keys.Get(s.Header.KeyID)
	if len(candidates) == 0 {
		return nil, UnknownSigner
	}
	var err error
	for _, el := range candidates {
		if err = s.VerifyKey(el, opts.Digest, opts.Hash); err == nil {
			return el, nil
		}
	}
	return nil, err
}

func (s Signature) VerifyKey(pub crypto.PublicKey, digest []byte, hash crypto.Hash) error {
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
