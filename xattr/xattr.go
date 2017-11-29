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

package xattr

import (
	"crypto"
	"io"
	"os"

	"golang.org/x/sys/unix"

	"pault.ag/go/ima"
)

var (
	// Files attribute to read and write IMA signatures to.
	IMAAttrName string = "security.ima"
)

// Load the ima signature from the filesystem xattr, and parse the Signature
// into an ima.Signature block.
//
// If the attribute doesn't exist, golang/x/sys/unix.ENODATA will be returned.
func Parse(fd *os.File) (*ima.Signature, error) {
	data := make([]byte, 1024)
	size, err := unix.Getxattr(fd.Name(), IMAAttrName, data)
	if err != nil {
		return nil, err
	}
	return ima.Parse(data[:size])
}

// Load the ima signature from the filesystem xattr, and measure the file's
// current digest against the signature's digest. If that's valid, the signature
// will be checked against all keys in the KeyPool that have the same Key ID,
// and will either return nil for a valid signature from one of the keys, or
// the last error for the last key tried.
//
// This code expects the file is seek'd to the origin of the file, and will return
// the file at its EOF.
func Verify(fd *os.File, pool ima.KeyPool) error {
	sig, err := Parse(fd)
	if err != nil {
		return err
	}
	hashFunc, err := sig.Header.Hash()
	if err != nil {
		return err
	}
	hash := hashFunc.New()
	if _, err = io.Copy(hash, fd); err != nil {
		return err
	}
	digest := hash.Sum(nil)

	_, err = sig.Verify(ima.VerifyOptions{
		Keys:   pool,
		Digest: digest,
		Hash:   *hashFunc,
	})
	return err
}

// Measure the file, and sign the digest with the provided signer. The entropy
// source and signer options will be passed directly back into the underlying
// Signature call.
//
// This code expects the file is seek'd to the origin of the file, and will return
// the file at its EOF.
func Sign(signer crypto.Signer, rand io.Reader, opts crypto.SignerOpts, fd *os.File) error {
	hash := opts.HashFunc().New()
	if _, err := io.Copy(hash, fd); err != nil {
		return err
	}
	digest := hash.Sum(nil)
	sig, err := ima.Sign(signer, rand, digest, opts)
	if err != nil {
		return err
	}
	return unix.Setxattr(fd.Name(), IMAAttrName, sig, 0x00)
}
