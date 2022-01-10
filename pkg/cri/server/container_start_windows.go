// +build windows

/*
Copyright 2017 The Kubernetes Authors.
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

package server

import (
	"os"

	"github.com/containerd/containerd"
	"golang.org/x/sys/windows"
)

func addOptWithNoPivotRoot(taskOpts []containerd.NewTaskOpts) []containerd.NewTaskOpts {
	// TODO: JTERRY75 - For LCOW we should actually forward this call all the
	// way to the runc in the guest.
	return taskOpts
}

func openContainerOutputFile(path string) (*os.File, error) {
	u16, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}

	h, err := windows.CreateFile(
		u16,
		windows.FILE_APPEND_DATA,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0)
	if err != nil {
		return nil, err
	}

	return os.NewFile(uintptr(h), path), nil
}
