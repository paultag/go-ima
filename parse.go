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
func PublicKeyId(pubKey crypto.PublicKey) ([4]byte, error) {
	derKey := []byte{}
	switch pubKey.(type) {
	case rsa.PublicKey:
		pubKey := pubKey.(rsa.PublicKey)
		return PublicKeyId(&pubKey)
	case *rsa.PublicKey:
		var err error
		rsaPublicKey := pubKey.(*rsa.PublicKey)
		derKey, err = asn1.Marshal(*rsaPublicKey)
		if err != nil {
			return [4]byte{}, err
		}
	default:
		return [4]byte{}, fmt.Errorf("ima: public key format not supported")
	}

	hash := sha1.New()
	hash.Write(derKey)
	hashSum := hash.Sum(nil)

	return [4]byte{hashSum[16], hashSum[17], hashSum[18], hashSum[19]}, nil
}

// IMA Signature encapsulation. This contains both the IMA Signature Header
// directly, as well as the Signature, in bytes.
type Signature struct {
	Header    SignatureHeader
	Signature []byte
}

// Internal structure to unpack an IMA signature onto. This will read out
// an IMA header from a binary stream, and provide enough context to read the
// reamining amount of data, or understand which key to find.
type SignatureHeader struct {

	// Always 0x03.
	Magic uint8

	// Either format 0x01, or format 0x02. This library only supports IMA
	// Version 0x02.
	Version uint8

	// IMA Hash Algorithm used. This is an awkwardly sorted enum of a mix
	// of total shit algorithms and moderately tolerable ones. The Hash type
	// in this library can be used to convert this to a sensible format, as
	// well as the Hash() helper.
	HashAlgorithm uint8

	// Last 4 bytes of a SHA1 hash of the ASN.1 DER encoded RSA Public Key.
	// This is mostly useful to act as a bloom-filter for candidate keys to
	// check the Signature against.
	KeyID [4]byte

	// Completely useless field. Please do not use this. This is used
	// in the underlying byte serialization to let consumers know
	// the length of the Signature data.
	//
	// Users of this library can be happy to go about their buisness by running
	// len(Signature) instead. When the Signature is serialized, this field
	// will be set to exactly that, overriding whatever the current value
	// is.
	SignatureLength uint16
}

// Get the native Go crypto.Hash used to compute the Hash that that signature
// is over. This can be used to hash data to generate the data to verify
// the signature against.
func (h SignatureHeader) Hash() (*crypto.Hash, error) {
	return HashFunctions.ToCrypto(h.HashAlgorithm)
}

// Take a Signature, and convert it to a byte array. This can be used
// to write out IMA EVM signatures.
func Serialize(signature Signature) ([]byte, error) {
	if signature.Header.Version != 0x02 {
		return nil, fmt.Errorf("ima: version 2 signatures are supported, only")
	}
	if signature.Signature == nil {
		return nil, fmt.Errorf("ima: refusing to serialize without a signature")
	}

	// XXX: check if signature is bigger than an uint16
	signature.Header.SignatureLength = uint16(len(signature.Signature))

	buf := []byte{}
	out := bytes.NewBuffer(buf)

	// Dump the header to the buffer
	if err := binary.Write(out, binary.BigEndian, signature.Header); err != nil {
		return nil, err
	}

	// Dump the Signature to the buffer
	if err := binary.Write(out, binary.BigEndian, signature.Signature); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// Take a byte array and return a new Signature object, containing the parsed
// headers and Signature. This can be used to verify IMA signatures.
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
