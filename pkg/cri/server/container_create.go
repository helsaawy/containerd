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
	"fmt"
	"strconv"
	"strings"

	"github.com/containerd/typeurl"
	imagespec "github.com/opencontainers/image-spec/specs-go/v1"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/validate"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/windows"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"

	containerstore "github.com/containerd/cri/pkg/store/container"
	"github.com/containerd/cri/pkg/util"
)

func init() {
	typeurl.Register(&containerstore.Metadata{},
		"github.com/containerd/cri/pkg/store/container", "Metadata")
}

// setOCIProcessArgs sets process args. It returns error if the final arg list
// is empty.
func setOCIProcessArgs(g *generator, config *runtime.ContainerConfig, image *imagespec.Image) error {
	command, args := config.GetCommand(), config.GetArgs()
	// The following logic is migrated from https://github.com/moby/moby/blob/master/daemon/commit.go
	// TODO(random-liu): Clearly define the commands overwrite behavior.
	if len(command) == 0 {
		// Copy array to avoid data race.
		if len(args) == 0 {
			args = append([]string{}, image.Config.Cmd...)
		}
		if command == nil {
			command = append([]string{}, image.Config.Entrypoint...)
		}
	}
	if len(command) == 0 && len(args) == 0 {
		return errors.New("no command specified")
	}
	var ignoreArgsEscaped bool
	if ignoreArgsEscapedAnno, ok := config.Annotations["microsoft.io/ignore-args-escaped"]; ok {
		ignoreArgsEscaped = ignoreArgsEscapedAnno == "true"
	}
	setProcessArgs(g, image.OS == "windows", image.Config.ArgsEscaped && !ignoreArgsEscaped, append(command, args...))
	return nil
}

// setProcessArgs sets either g.Config.Process.CommandLine or g.Config.Process.Args.
// This is forked from g.SetProcessArgs to add argsEscaped support.
func setProcessArgs(g *generator, isWindows bool, argsEscaped bool, args []string) {
	logrus.WithFields(logrus.Fields{
		"isWindows":   isWindows,
		"argsEscaped": argsEscaped,
		"args":        args,
	}).Info("Setting process args on OCI spec")
	if g.Config == nil {
		g.Config = &runtimespec.Spec{}
	}
	if g.Config.Process == nil {
		g.Config.Process = &runtimespec.Process{}
	}

	if isWindows && argsEscaped {
		// argsEscaped is used for Windows containers to indicate that the command line should be
		// used from args[0] without escaping. This case seems to mostly result from use of
		// shell-form ENTRYPOINT or CMD in the Dockerfile. argsEscaped is a non-standard OCI
		// extension but we are using it here to support Docker images that rely on it. In the
		// future we should move to some properly standardized support in upstream OCI.
		// This logic is taken from https://github.com/moby/moby/blob/24f173a003727611aa482a55b812e0e39c67be65/daemon/oci_windows.go#L244
		//
		// Note: The approach taken here causes ArgsEscaped to change how commands passed directly
		// via CRI are interpreted as well. However, this actually matches with Docker's behavior
		// regarding commands specified at container create time, and seems non-trivial to fix,
		// so going to leave this way for now.
		g.Config.Process.CommandLine = args[0]
		if len(args[1:]) > 0 {
			g.Config.Process.CommandLine += " " + escapeArgs(args[1:])
		}
	} else {
		g.Config.Process.Args = args
	}
}

// escapeArgs makes a Windows-style escaped command line from a set of arguments
func escapeArgs(args []string) string {
	escapedArgs := make([]string, len(args))
	for i, a := range args {
		escapedArgs[i] = windows.EscapeArg(a)
	}
	return strings.Join(escapedArgs, " ")
}

// addImageEnvs adds environment variables from image config. It returns error if
// an invalid environment variable is encountered.
func addImageEnvs(g *generator, imageEnvs []string) error {
	for _, e := range imageEnvs {
		kv := strings.SplitN(e, "=", 2)
		if len(kv) != 2 {
			return errors.Errorf("invalid environment variable %q", e)
		}
		g.AddProcessEnv(kv[0], kv[1])
	}
	return nil
}

func setOCIPrivileged(g *generator, config *runtime.ContainerConfig) error {
	// Add all capabilities in privileged mode.
	g.SetupPrivileged(true)
	setOCIBindMountsPrivileged(g)
	if err := setOCIDevicesPrivileged(g); err != nil {
		return errors.Wrapf(err, "failed to set devices mapping %+v", config.GetDevices())
	}
	return nil
}

func clearReadOnly(m *runtimespec.Mount) {
	var opt []string
	for _, o := range m.Options {
		if o != "ro" {
			opt = append(opt, o)
		}
	}
	m.Options = append(opt, "rw")
}

// setOCILinuxResourceCgroup set container cgroup resource limit.
func setOCILinuxResourceCgroup(g *generator, resources *runtime.LinuxContainerResources) {
	if resources == nil {
		return
	}
	g.SetLinuxResourcesCPUPeriod(uint64(resources.GetCpuPeriod()))
	g.SetLinuxResourcesCPUQuota(resources.GetCpuQuota())
	g.SetLinuxResourcesCPUShares(uint64(resources.GetCpuShares()))
	g.SetLinuxResourcesMemoryLimit(resources.GetMemoryLimitInBytes())
	g.SetLinuxResourcesCPUCpus(resources.GetCpusetCpus())
	g.SetLinuxResourcesCPUMems(resources.GetCpusetMems())
}

// setOCILinuxResourceOOMScoreAdj set container OOMScoreAdj resource limit.
func setOCILinuxResourceOOMScoreAdj(g *generator, resources *runtime.LinuxContainerResources, restrictOOMScoreAdjFlag bool) error {
	if resources == nil {
		return nil
	}
	adj := int(resources.GetOomScoreAdj())
	if restrictOOMScoreAdjFlag {
		var err error
		adj, err = restrictOOMScoreAdj(adj)
		if err != nil {
			return err
		}
	}
	g.SetProcessOOMScoreAdj(adj)

	return nil
}

func setOCIBindMountsPrivileged(g *generator) {
	spec := g.Config
	// clear readonly for /sys and cgroup
	for i, m := range spec.Mounts {
		if spec.Mounts[i].Destination == "/sys" {
			clearReadOnly(&spec.Mounts[i])
		}
		if m.Type == "cgroup" {
			clearReadOnly(&spec.Mounts[i])
		}
	}
	spec.Linux.ReadonlyPaths = nil
	spec.Linux.MaskedPaths = nil
}

// setOCINamespace sets the correct namespace value in the OCI spec based on the CRI namespace mode.
func setOCINamespace(g *generator, mode runtime.NamespaceMode, nsName string, podNS string) error {
	switch mode {
	case runtime.NamespaceMode_POD:
		// Use the pod's namespace.
		return g.AddOrReplaceLinuxNamespace(nsName, podNS)
	case runtime.NamespaceMode_CONTAINER:
		// Empty path will cause the OCI runtime to create a new container ns.
		return g.AddOrReplaceLinuxNamespace(nsName, "")
	case runtime.NamespaceMode_NODE:
		// NS not in the spec at all will cause it to inherit from the runtime (host).
		return g.RemoveLinuxNamespace(nsName)
	}
	return fmt.Errorf("unsupported namespace mode for %s: %d", nsName, mode)
}

// setOCINamespaces sets namespaces.
func setOCINamespaces(g *generator, namespaces *runtime.NamespaceOption, sandboxPid uint32) error {
	if err := setOCINamespace(g, namespaces.GetNetwork(), string(runtimespec.NetworkNamespace), getNetworkNamespace(sandboxPid)); err != nil {
		return err
	}
	if err := setOCINamespace(g, namespaces.GetIpc(), string(runtimespec.IPCNamespace), getIPCNamespace(sandboxPid)); err != nil {
		return err
	}
	if err := setOCINamespace(g, namespaces.GetPid(), string(runtimespec.PIDNamespace), getPIDNamespace(sandboxPid)); err != nil {
		return err
	}
	// CRI does not have a namespace option for UTS, so use the pod's namespace.
	if err := setOCINamespace(g, runtime.NamespaceMode_POD, string(runtimespec.UTSNamespace), getUTSNamespace(sandboxPid)); err != nil {
		return err
	}
	return nil
}

// generateUserString generates valid user string based on OCI Image Spec
// v1.0.0.
//
// CRI defines that the following combinations are valid:
//
// uid, uid/gid, username, username/gid
//
// TODO(random-liu): Add group name support in CRI.
func generateUserString(username string, uid, gid *runtime.Int64Value) (string, error) {
	var userstr, groupstr string
	if uid != nil {
		userstr = strconv.FormatInt(uid.GetValue(), 10)
	}
	if username != "" {
		userstr = username
	}
	if gid != nil {
		groupstr = strconv.FormatInt(gid.GetValue(), 10)
	}
	if userstr == "" {
		if groupstr != "" {
			return "", errors.Errorf("user group %q is specified without user", groupstr)
		}
		return "", nil
	}
	if groupstr != "" {
		userstr = userstr + ":" + groupstr
	}
	return userstr, nil
}

// getOCICapabilitiesList returns a list of all available capabilities.
func getOCICapabilitiesList() []string {
	var caps []string
	for _, cap := range capability.List() {
		if cap > validate.LastCap() {
			continue
		}
		caps = append(caps, "CAP_"+strings.ToUpper(cap.String()))
	}
	return caps
}

// Adds capabilities to all sets relevant to root (bounding, permitted, effective, inheritable)
func addProcessRootCapability(g *generator, c string) error {
	if err := g.AddProcessCapabilityBounding(c); err != nil {
		return err
	}
	if err := g.AddProcessCapabilityPermitted(c); err != nil {
		return err
	}
	if err := g.AddProcessCapabilityEffective(c); err != nil {
		return err
	}
	if err := g.AddProcessCapabilityInheritable(c); err != nil {
		return err
	}
	return nil
}

// Drops capabilities to all sets relevant to root (bounding, permitted, effective, inheritable)
func dropProcessRootCapability(g *generator, c string) error {
	if err := g.DropProcessCapabilityBounding(c); err != nil {
		return err
	}
	if err := g.DropProcessCapabilityPermitted(c); err != nil {
		return err
	}
	if err := g.DropProcessCapabilityEffective(c); err != nil {
		return err
	}
	if err := g.DropProcessCapabilityInheritable(c); err != nil {
		return err
	}
	return nil
}

// setOCICapabilities adds/drops process capabilities.
func setOCICapabilities(g *generator, capabilities *runtime.Capability) error {
	if capabilities == nil {
		return nil
	}

	// Add/drop all capabilities if "all" is specified, so that
	// following individual add/drop could still work. E.g.
	// AddCapabilities: []string{"ALL"}, DropCapabilities: []string{"CHOWN"}
	// will be all capabilities without `CAP_CHOWN`.
	if util.InStringSlice(capabilities.GetAddCapabilities(), "ALL") {
		for _, c := range getOCICapabilitiesList() {
			if err := addProcessRootCapability(g, c); err != nil {
				return err
			}
		}
	}
	if util.InStringSlice(capabilities.GetDropCapabilities(), "ALL") {
		for _, c := range getOCICapabilitiesList() {
			if err := dropProcessRootCapability(g, c); err != nil {
				return err
			}
		}
	}

	for _, c := range capabilities.GetAddCapabilities() {
		if strings.ToUpper(c) == "ALL" {
			continue
		}
		// Capabilities in CRI doesn't have `CAP_` prefix, so add it.
		if err := addProcessRootCapability(g, "CAP_"+strings.ToUpper(c)); err != nil {
			return err
		}
	}

	for _, c := range capabilities.GetDropCapabilities() {
		if strings.ToUpper(c) == "ALL" {
			continue
		}
		if err := dropProcessRootCapability(g, "CAP_"+strings.ToUpper(c)); err != nil {
			return err
		}
	}
	return nil
}
