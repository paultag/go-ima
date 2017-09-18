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
	"bytes"
	"fmt"
	"io/ioutil"

	"encoding/asn1"
	"encoding/binary"

	"crypto"
	"crypto/rsa"
	"crypto/sha1"
)

// IMA creates a content-based ID to help validate signatures which is based
// on a hash the public key. In particular, it's the last 4 bytes of a SHA1
// hash of the DER encoded RSA Public Key. Other formates are not supported
// at this time.
func PublicKeyId(pubKey crypto.PublicKey) ([]byte, error) {
	derKey := []byte{}
	switch pubKey.(type) {
	case *rsa.PublicKey:
		var err error
		rsaPublicKey := pubKey.(*rsa.PublicKey)
		derKey, err = asn1.Marshal(*rsaPublicKey)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("ima: public key format not supported")
	}

	hash := sha1.New()
	hash.Write(derKey)
	hashSum := hash.Sum(nil)

	return hashSum[16:20], nil
}

// IMA Signature
type Signature struct {
	Header    SignatureHeader
	Signature []byte
}

// Internal structure to unpack an IMA signature onto. This will read out
// an IMA header from a binary stream, and provide enough context to read the
// reamining amount of data, or understand which key to find.
type SignatureHeader struct {
	Magic           uint8
	Version         uint8
	HashAlgorithm   uint8
	KeyID           [4]byte
	SignatureLength uint16
}

func (h SignatureHeader) Hash() (*crypto.Hash, error) {
	return HashFunctions.IMAToGo(h.HashAlgorithm)
}

func Serialize(signature Signature) ([]byte, error) {
	if signature.Signature == nil {
		return nil, fmt.Errorf("ima: refusing to serialize without a signature")
	}

	// XXX: check if signature is bigger than an uint16
	signature.Header.SignatureLength = uint16(len(signature.Signature))

	buf := []byte{}
	out := bytes.NewBuffer(buf)

	if err := binary.Write(out, binary.BigEndian, signature.Header); err != nil {
		return nil, err
	}

	if err := binary.Write(out, binary.BigEndian, signature.Signature); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

func Parse(signature []byte) (*Signature, error) {
	data := bytes.NewReader(signature)
	line := SignatureHeader{}

	if err := binary.Read(data, binary.BigEndian, &line); err != nil {
		return nil, err
	}
	if line.Magic != 0x03 {
		return nil, fmt.Errorf("ima: input data is in a bad format")
	}

	imaSignature, err := ioutil.ReadAll(data)
	if err != nil {
		return nil, err
	}
	if len(imaSignature) != int(line.SignatureLength) {
		return nil, fmt.Errorf(
			"ima: expected signature length of %d, got %d",
			line.SignatureLength,
			len(imaSignature),
		)
	}

	return &Signature{
		Header:    line,
		Signature: imaSignature,
	}, nil
}
