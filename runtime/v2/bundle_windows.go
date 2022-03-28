//go:build windows
// +build windows

/*
   Copyright The containerd Authors.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package v2

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
)

const nRetries = 3
const retryWait = 100 * time.Millisecond

// atomicDelete renames the path to a hidden file before removal
func atomicDelete(path string) error {
	// create a hidden dir for an atomic removal
	atomicPath := filepath.Join(filepath.Dir(path), fmt.Sprintf(".%s", filepath.Base(path)))
	// Windows places a lock on a process's working directory, so, unlike Linux, you cannot delete
	// if the process is still running.
	// Add retries with wait to allow the shim to fully exit.
	var err error
	for i := 1; i <= nRetries; i++ {
		if err = os.Rename(path, atomicPath); err != nil {
			logrus.Debugf("bundle %q atomic delete attempt #%d failed: %v", path, i, err)
			if os.IsNotExist(err) {
				return nil
			}
			if i != nRetries && errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
				time.Sleep(retryWait)
				continue
			}
			return err
		}
		break
	}
	return os.RemoveAll(atomicPath)
}
