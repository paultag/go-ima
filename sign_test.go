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
