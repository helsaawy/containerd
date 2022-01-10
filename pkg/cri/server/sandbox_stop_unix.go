//go:build !windows
// +build !windows

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
	"context"

	"github.com/containerd/containerd/log"
	"github.com/pkg/errors"

	sandboxstore "github.com/containerd/containerd/pkg/cri/store/sandbox"
)

func (c *criService) doStopPodSandbox(ctx context.Context, id string, sandbox sandboxstore.Sandbox) error {
	// Teardown network for sandbox.
	if sandbox.NetNS != nil {
		netNSPath := sandbox.NetNSPath
		// Use empty netns path if netns is not available. This is defined in:
		// https://github.com/containernetworking/cni/blob/v0.7.0-alpha1/SPEC.md
		if closed, err := sandbox.NetNS.Closed(); err != nil {
			return errors.Wrap(err, "failed to check network namespace closed")
		} else if closed {
			netNSPath = ""
		}
		if err := c.teardownPod(id, netNSPath, sandbox.Config); err != nil {
			return errors.Wrapf(err, "failed to destroy network for sandbox %q", id)
		}
		if err := sandbox.NetNS.Remove(); err != nil {
			return errors.Wrapf(err, "failed to remove network namespace for sandbox %q", id)
		}
	}

	log.G(ctx).Infof("TearDown network for sandbox %q successfully", id)

	return nil
}
