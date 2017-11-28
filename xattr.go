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

	"golang.org/x/sys/unix"
)

// Load the security.ima xattr from a given file, and return a new Signature
// object, containing the parsed headers and Signature.
func ParseXattr(path string) (*Signature, error) {
	data := make([]byte, 1024)
	sz, err := unix.Getxattr(path, "security.ima", data)
	if err != nil {
		return nil, err
	}
	if sz > 1024 {
		return nil, fmt.Errorf("ima: xattr: overlarge xattr, I'm confused")
	}
	return Parse(data[:sz])
}
