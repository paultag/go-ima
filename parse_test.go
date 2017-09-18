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

package ima_test

import (
	"bytes"
	"testing"

	"pault.ag/go/ima"
)

func TestParse(t *testing.T) {
	signature, err := ima.Parse([]byte{
		3, 2, 2, 219, 31, 247, 42, 0, 128, 22, 197, 147, 56, 114, 32, 162, 173,
		218, 153, 9, 105, 216, 122, 86, 168, 162, 78, 236, 229, 30, 54, 137,
		253, 34, 156, 76, 86, 231, 253, 221, 78, 185, 159, 54, 12, 46, 227,
		255, 15, 99, 68, 222, 36, 236, 211, 38, 63, 76, 122, 116, 172, 100,
		152, 64, 61, 124, 233, 233, 134, 94, 77, 47, 50, 82, 45, 231, 158, 150,
		208, 203, 38, 93, 91, 42, 184, 254, 84, 149, 60, 229, 61, 94, 89, 165,
		20, 96, 246, 125, 24, 226, 203, 172, 180, 118, 94, 169, 127, 45, 156,
		221, 32, 101, 129, 109, 80, 251, 116, 230, 49, 239, 212, 194, 224, 124,
		114, 192, 31, 217, 176, 249, 227, 239, 198, 217, 26, 120, 157,
	})
	isok(t, err)

	assert(t, signature.Header.Magic == 0x03)
	assert(t, signature.Header.Version == 0x02)
	assert(t, signature.Header.HashAlgorithm == 0x02)
	assert(t, bytes.Compare(signature.Header.KeyID[:], []byte{0xdb, 0x1f, 0xf7, 0x2a}) == 0)

	assert(t, len(signature.Signature) == 128)
	assert(t, len(signature.Signature) == int(signature.Header.SignatureLength))
}

func TestRoundTrip(t *testing.T) {
	signature, err := ima.Parse([]byte{
		3, 2, 2, 219, 31, 247, 42, 0, 128, 22, 197, 147, 56, 114, 32, 162, 173,
		218, 153, 9, 105, 216, 122, 86, 168, 162, 78, 236, 229, 30, 54, 137,
		253, 34, 156, 76, 86, 231, 253, 221, 78, 185, 159, 54, 12, 46, 227,
		255, 15, 99, 68, 222, 36, 236, 211, 38, 63, 76, 122, 116, 172, 100,
		152, 64, 61, 124, 233, 233, 134, 94, 77, 47, 50, 82, 45, 231, 158, 150,
		208, 203, 38, 93, 91, 42, 184, 254, 84, 149, 60, 229, 61, 94, 89, 165,
		20, 96, 246, 125, 24, 226, 203, 172, 180, 118, 94, 169, 127, 45, 156,
		221, 32, 101, 129, 109, 80, 251, 116, 230, 49, 239, 212, 194, 224, 124,
		114, 192, 31, 217, 176, 249, 227, 239, 198, 217, 26, 120, 157,
	})
	isok(t, err)

	buf, err := ima.Serialize(*signature)
	isok(t, err)

	signature, err = ima.Parse(buf)
	isok(t, err)

	assert(t, signature.Header.Magic == 0x03)
	assert(t, signature.Header.Version == 0x02)
	assert(t, signature.Header.HashAlgorithm == 0x02)
	assert(t, bytes.Compare(signature.Header.KeyID[:], []byte{0xdb, 0x1f, 0xf7, 0x2a}) == 0)

	assert(t, len(signature.Signature) == 128)
	assert(t, len(signature.Signature) == int(signature.Header.SignatureLength))
}
