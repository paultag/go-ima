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
