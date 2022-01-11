//go:build windows
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

package client

import (
	"context"
	"net"
	"strings"

	"github.com/Microsoft/go-winio"
	"github.com/containerd/containerd/integration/util"
)

// GetAddressAndDialer returns a local Windows named pipe dialer if 'endpoint'
// is a named pipe path else returns a dialer for the specific protocol.
func GetAddressAndDialer(endpoint string) (string, func(ctx context.Context, addr string) (net.Conn, error), error) {
	if strings.HasPrefix(endpoint, "\\\\.\\pipe") {
		return endpoint, dial, nil
	}
	return util.GetAddressAndDialer(endpoint)
}

func dial(ctx context.Context, addr string) (net.Conn, error) {
	return winio.DialPipeContext(ctx, addr)
}
