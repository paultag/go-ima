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
	"crypto"
	"fmt"
)

// Encapsulation of an IMA EVM Hash function. These should likely not be used
// directly - talking directly about crypto.Hash numbers is much safer. This
// part of the IMA EVM library is useful to convert between IMA EVM Hash IDs and the
// standard Go crypto Hash objects.
//
// These objects are only exported in the event that someone needs a very
// precise understanding of the mapping between IMA EVM hashes and the native
// Go hashes.
type Hash struct {
	Id   uint8
	Hash crypto.Hash
}

// List of IMA EVM Hash functions.
type Hashes []Hash

// Convert a crypto.Hash to an ima.Hash. This will enumerate the Hash
// functions in the Hashes, and find an IMA EVM Hash object that corresponds
// to the native Go Hash function.
func (h Hashes) ToHash(hash crypto.Hash) (*Hash, error) {
	for _, imaHash := range h {
		if imaHash.Hash == hash {
			return &imaHash, nil
		}
	}
	return nil, fmt.Errorf("ima: no matching crypto.Hash found")
}

// Convert a ima.Hash to a crypto.Hash. This will enumerate the Hsah
// functions in the Hashes, and find a crypto.hash that corresponds
// to the IMA EVM hash ID.
func (h Hashes) ToCrypto(hash uint8) (*crypto.Hash, error) {
	for _, imaHash := range h {
		if imaHash.Id == hash {
			return &imaHash.Hash, nil
		}
	}
	return nil, fmt.Errorf("ima: no matching IMA EVM hash found")
}

var (
	MD4 Hash = Hash{Id: 0, Hash: crypto.MD4}
	MD5 Hash = Hash{Id: 1, Hash: crypto.MD5}

	RIPEMD160 Hash = Hash{Id: 3, Hash: crypto.RIPEMD160}

	SHA1   Hash = Hash{Id: 2, Hash: crypto.SHA1}
	SHA224 Hash = Hash{Id: 7, Hash: crypto.SHA224}
	SHA256 Hash = Hash{Id: 4, Hash: crypto.SHA256}
	SHA384 Hash = Hash{Id: 5, Hash: crypto.SHA384}
	SHA512 Hash = Hash{Id: 6, Hash: crypto.SHA512}

	// List of all Hash functions.
	HashFunctions = Hashes{
		MD4, MD5,
		RIPEMD160,
		SHA1, SHA224, SHA256, SHA384, SHA512,
	}
)
