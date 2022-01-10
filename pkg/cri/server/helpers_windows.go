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
	runhcsoptions "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	criconfig "github.com/containerd/cri/pkg/config"
	"github.com/pkg/errors"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

// initSelinuxOpts is not supported on Windows.
func initSelinuxOpts(selinuxOpt *runtime.SELinuxOption) (string, string, error) {
	return "", "", nil
}

func (c *criService) getSandboxPlatform(sandboxID string) (string, error) {
	sandbox, err := c.sandboxStore.Get(sandboxID)
	if err != nil {
		return "", err
	}

	// Get the RuntimeHandler config overrides
	var ociRuntime criconfig.Runtime
	if sandbox.RuntimeHandler != "" {
		ociRuntime = c.config.Runtimes[sandbox.RuntimeHandler]
	} else {
		ociRuntime = c.config.DefaultRuntime
	}
	runtimeOpts, err := generateRuntimeOptions(ociRuntime, c.config)
	if err != nil {
		return "", errors.Wrap(err, "failed to generate runtime options")
	}
	rhcso := runtimeOpts.(*runhcsoptions.Options)
	sandboxPlatform := rhcso.SandboxPlatform
	if sandboxPlatform == "" {
		sandboxPlatform = "windows/amd64"
	}
	return sandboxPlatform, nil
}
