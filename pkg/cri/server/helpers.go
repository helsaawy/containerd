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

package server

import (
	"context"
	"fmt"
	"path"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/errdefs"
	clabels "github.com/containerd/containerd/labels"
	criconfig "github.com/containerd/containerd/pkg/cri/config"
	containerstore "github.com/containerd/containerd/pkg/cri/store/container"
	imagestore "github.com/containerd/containerd/pkg/cri/store/image"
	sandboxstore "github.com/containerd/containerd/pkg/cri/store/sandbox"
	runtimeoptions "github.com/containerd/containerd/pkg/runtimeoptions/v1"
	"github.com/containerd/containerd/plugin"
	"github.com/containerd/containerd/reference/docker"
	"github.com/containerd/containerd/runtime/linux/runctypes"
	runcoptions "github.com/containerd/containerd/runtime/v2/runc/options"
	"github.com/containerd/typeurl"
	"github.com/sirupsen/logrus"

	runhcsoptions "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/options"
	imagedigest "github.com/opencontainers/go-digest"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/generate"
	"github.com/pelletier/go-toml"
	"github.com/pkg/errors"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

const (
	// errorStartReason is the exit reason when fails to start container.
	errorStartReason = "StartError"
	// errorStartExitCode is the exit code when fails to start container.
	// 128 is the same with Docker's behavior.
	// TODO(windows): Figure out what should be used for windows.
	errorStartExitCode = 128
	// completeExitReason is the exit reason when container exits with code 0.
	completeExitReason = "Completed"
	// errorExitReason is the exit reason when container exits with code non-zero.
	errorExitReason = "Error"
	// oomExitReason is the exit reason when process in container is oom killed.
	oomExitReason = "OOMKilled"

	// defaultSandboxOOMAdj is default omm adj for sandbox container. (kubernetes#47938).
	defaultSandboxOOMAdj = -998
	// defaultSandboxCPUshares is default cpu shares for sandbox container.
	defaultSandboxCPUshares = 2
	// defaultShmSize is the default size of the sandbox shm.
	defaultShmSize = int64(1024 * 1024 * 64)
	// relativeRootfsPath is the rootfs path relative to bundle path.
	relativeRootfsPath = "rootfs"

	// sandboxesDir contains all sandbox root. A sandbox root is the running
	// directory of the sandbox, all files created for the sandbox will be
	// placed under this directory.
	sandboxesDir = "sandboxes"
	// containersDir contains all container root.
	containersDir = "containers"

	// According to http://man7.org/linux/man-pages/man5/resolv.conf.5.html:
	// "The search list is currently limited to six domains with a total of 256 characters."
	maxDNSSearches = 6

	// Delimiter used to construct container/sandbox names.
	nameDelimiter = "_"

	// criContainerdPrefix is common prefix for cri-containerd
	criContainerdPrefix = "io.cri-containerd"
	// containerKindLabel is a label key indicating container is sandbox container or application container
	containerKindLabel = criContainerdPrefix + ".kind"
	// containerKindSandbox is a label value indicating container is sandbox container
	containerKindSandbox = "sandbox"
	// containerKindContainer is a label value indicating container is application container
	containerKindContainer = "container"
	// imageLabelKey is the label key indicating the image is managed by cri plugin.
	imageLabelKey = criContainerdPrefix + ".image"
	// imageLabelValue is the label value indicating the image is managed by cri plugin.
	imageLabelValue = "managed"
	// sandboxMetadataExtension is an extension name that identify metadata of sandbox in CreateContainerRequest
	sandboxMetadataExtension = criContainerdPrefix + ".sandbox.metadata"
	// containerMetadataExtension is an extension name that identify metadata of container in CreateContainerRequest
	containerMetadataExtension = criContainerdPrefix + ".container.metadata"

	// netNSFormat is the format of network namespace of a process.
	netNSFormat = "/proc/%v/ns/net"
	// ipcNSFormat is the format of ipc namespace of a process.
	ipcNSFormat = "/proc/%v/ns/ipc"
	// utsNSFormat is the format of uts namespace of a process.
	utsNSFormat = "/proc/%v/ns/uts"
	// pidNSFormat is the format of pid namespace of a process.
	pidNSFormat = "/proc/%v/ns/pid"
	// devShm is the default path of /dev/shm.
	devShm = "/dev/shm"
	// etcHosts is the default path of /etc/hosts file.
	etcHosts = "/etc/hosts"
	// etcHostname is the default path of /etc/hostname file.
	etcHostname = "/etc/hostname"
	// resolvConfPath is the abs path of resolv.conf on host or container.
	resolvConfPath = "/etc/resolv.conf"
	// hostnameEnv is the key for HOSTNAME env.
	hostnameEnv = "HOSTNAME"

	// defaultIfName is the default network interface for the pods
	defaultIfName = "eth0"

	// networkAttachCount is the minimum number of networks the PodSandbox
	// attaches to
	networkAttachCount        = 2
	windowsNetworkAttachCount = 1
)

// makeSandboxName generates sandbox name from sandbox metadata. The name
// generated is unique as long as sandbox metadata is unique.
func makeSandboxName(s *runtime.PodSandboxMetadata) string {
	return strings.Join([]string{
		s.Name,                       // 0
		s.Namespace,                  // 1
		s.Uid,                        // 2
		fmt.Sprintf("%d", s.Attempt), // 3
	}, nameDelimiter)
}

// makeContainerName generates container name from sandbox and container metadata.
// The name generated is unique as long as the sandbox container combination is
// unique.
func makeContainerName(c *runtime.ContainerMetadata, s *runtime.PodSandboxMetadata) string {
	return strings.Join([]string{
		c.Name,                       // 0: container name
		s.Name,                       // 1: pod name
		s.Namespace,                  // 2: pod namespace
		s.Uid,                        // 3: pod uid
		fmt.Sprintf("%d", c.Attempt), // 4: attempt number of creating the container
	}, nameDelimiter)
}

// getSandboxRootDir returns the root directory for managing sandbox files,
// e.g. hosts files.
func (c *criService) getSandboxRootDir(id string) string {
	return filepath.Join(c.config.RootDir, sandboxesDir, id)
}

// getVolatileSandboxRootDir returns the root directory for managing volatile sandbox files,
// e.g. named pipes.
func (c *criService) getVolatileSandboxRootDir(id string) string {
	return filepath.Join(c.config.StateDir, sandboxesDir, id)
}

// getContainerRootDir returns the root directory for managing container files,
// e.g. state checkpoint.
func (c *criService) getContainerRootDir(id string) string {
	return filepath.Join(c.config.RootDir, containersDir, id)
}

// getVolatileContainerRootDir returns the root directory for managing volatile container files,
// e.g. named pipes.
func (c *criService) getVolatileContainerRootDir(id string) string {
	return filepath.Join(c.config.StateDir, containersDir, id)
}

// getSandboxHostname returns the hostname file path inside the sandbox root directory.
func (c *criService) getSandboxHostname(id string) string {
	return filepath.Join(c.getSandboxRootDir(id), "hostname")
}

// getSandboxHosts returns the hosts file path inside the sandbox root directory.
func (c *criService) getSandboxHosts(id string) string {
	return filepath.Join(c.getSandboxRootDir(id), "hosts")
}

// getResolvPath returns resolv.conf filepath for specified sandbox.
func (c *criService) getResolvPath(id string) string {
	return filepath.Join(c.getSandboxRootDir(id), "resolv.conf")
}

// getSandboxDevShm returns the shm file path inside the sandbox root directory.
func (c *criService) getSandboxDevShm(id string) string {
	return filepath.Join(c.getVolatileSandboxRootDir(id), "shm")
}

// getNetworkNamespace returns the network namespace of a process.
func getNetworkNamespace(pid uint32) string {
	return fmt.Sprintf(netNSFormat, pid)
}

// getIPCNamespace returns the ipc namespace of a process.
func getIPCNamespace(pid uint32) string {
	return fmt.Sprintf(ipcNSFormat, pid)
}

// getUTSNamespace returns the uts namespace of a process.
func getUTSNamespace(pid uint32) string {
	return fmt.Sprintf(utsNSFormat, pid)
}

// getPIDNamespace returns the pid namespace of a process.
func getPIDNamespace(pid uint32) string {
	return fmt.Sprintf(pidNSFormat, pid)
}

// criContainerStateToString formats CRI container state to string.
func criContainerStateToString(state runtime.ContainerState) string {
	return runtime.ContainerState_name[int32(state)]
}

// getRepoDigestAngTag returns image repoDigest and repoTag of the named image reference.
func getRepoDigestAndTag(namedRef docker.Named, digest imagedigest.Digest, schema1 bool) (string, string) {
	var repoTag, repoDigest string
	if _, ok := namedRef.(docker.NamedTagged); ok {
		repoTag = namedRef.String()
	}
	if _, ok := namedRef.(docker.Canonical); ok {
		repoDigest = namedRef.String()
	} else if !schema1 {
		// digest is not actual repo digest for schema1 image.
		repoDigest = namedRef.Name() + "@" + digest.String()
	}
	return repoDigest, repoTag
}

// localResolve resolves image reference locally and returns corresponding image metadata. It
// returns store.ErrNotExist if the reference doesn't exist.
func (c *criService) localResolve(refOrID string) (imagestore.Image, error) {
	getImageID := func(refOrId string) string {
		if _, err := imagedigest.Parse(refOrID); err == nil {
			return refOrID
		}
		return func(ref string) string {
			// ref is not image id, try to resolve it locally.
			// TODO(random-liu): Handle this error better for debugging.
			normalized, err := docker.ParseDockerRef(ref)
			if err != nil {
				return ""
			}
			id, err := c.imageStore.Resolve(normalized.String())
			if err != nil {
				return ""
			}
			return id
		}(refOrID)
	}

	imageID := getImageID(refOrID)
	if imageID == "" {
		// Try to treat ref as imageID
		imageID = refOrID
	}
	return c.imageStore.Get(imageID)
}

// toContainerdImage converts an image object in image store to containerd image handler.
func (c *criService) toContainerdImage(ctx context.Context, image imagestore.Image) (containerd.Image, error) {
	// image should always have at least one reference.
	if len(image.References) == 0 {
		return nil, errors.Errorf("invalid image with no reference %q", image.ID)
	}
	return c.client.GetImage(ctx, image.References[0])
}

// getUserFromImage gets uid or user name of the image user.
// If user is numeric, it will be treated as uid; or else, it is treated as user name.
func getUserFromImage(user string) (*int64, string) {
	// return both empty if user is not specified in the image.
	if user == "" {
		return nil, ""
	}
	// split instances where the id may contain user:group
	user = strings.Split(user, ":")[0]
	// user could be either uid or user name. Try to interpret as numeric uid.
	uid, err := strconv.ParseInt(user, 10, 64)
	if err != nil {
		// If user is non numeric, assume it's user name.
		return nil, user
	}
	// If user is a numeric uid.
	return &uid, ""
}

// ensureImageExists returns corresponding metadata of the image reference, if image is not
// pulled yet, the function will pull the image.
func (c *criService) ensureImageExists(ctx context.Context, ref string, config *runtime.PodSandboxConfig) (*imagestore.Image, error) {
	image, err := c.localResolve(ref)
	if err != nil && !errdefs.IsNotFound(err) {
		return nil, errors.Wrapf(err, "failed to get image %q", ref)
	}
	if err == nil {
		return &image, nil
	}
	// Pull image to ensure the image exists
	resp, err := c.PullImage(ctx, &runtime.PullImageRequest{Image: &runtime.ImageSpec{Image: ref}, SandboxConfig: config})
	if err != nil {
		return nil, errors.Wrapf(err, "failed to pull image %q", ref)
	}
	imageID := resp.GetImageRef()
	newImage, err := c.imageStore.Get(imageID)
	if err != nil {
		// It's still possible that someone removed the image right after it is pulled.
		return nil, errors.Wrapf(err, "failed to get image %q after pulling", imageID)
	}
	return &newImage, nil
}

// validateTargetContainer checks that a container is a valid
// target for a container using PID NamespaceMode_TARGET.
// The target container must be in the same sandbox and must be running.
// Returns the target container for convenience.
func (c *criService) validateTargetContainer(sandboxID, targetContainerID string) (containerstore.Container, error) {
	targetContainer, err := c.containerStore.Get(targetContainerID)
	if err != nil {
		return containerstore.Container{}, errors.Wrapf(err, "container %q does not exist", targetContainerID)
	}

	targetSandboxID := targetContainer.Metadata.SandboxID
	if targetSandboxID != sandboxID {
		return containerstore.Container{},
			errors.Errorf("container %q (sandbox %s) does not belong to sandbox %s", targetContainerID, targetSandboxID, sandboxID)
	}

	status := targetContainer.Status.Get()
	if state := status.State(); state != runtime.ContainerState_CONTAINER_RUNNING {
		return containerstore.Container{}, errors.Errorf("container %q is not running - in state %s", targetContainerID, state)
	}

	return targetContainer, nil
}

// isInCRIMounts checks whether a destination is in CRI mount list.
func isInCRIMounts(dst string, mounts []*runtime.Mount) bool {
	for _, m := range mounts {
		if filepath.Clean(m.ContainerPath) == filepath.Clean(dst) {
			return true
		}
	}
	return false
}

// filterLabel returns a label filter. Use `%q` here because containerd
// filter needs extra quote to work properly.
func filterLabel(k, v string) string {
	return fmt.Sprintf("labels.%q==%q", k, v)
}

// buildLabel builds the labels from config to be passed to containerd
func buildLabels(configLabels, imageConfigLabels map[string]string, containerType string) map[string]string {
	labels := make(map[string]string)

	for k, v := range imageConfigLabels {
		if err := clabels.Validate(k, v); err == nil {
			labels[k] = v
		} else {
			// In case the image label is invalid, we output a warning and skip adding it to the
			// container.
			logrus.WithError(err).Warnf("unable to add image label with key %s to the container", k)
		}
	}
	// labels from the CRI request (config) will override labels in the image config
	for k, v := range configLabels {
		labels[k] = v
	}
	labels[containerKindLabel] = containerType
	return labels
}

// newSpecGenerator creates a new spec generator for the runtime spec.
func newSpecGenerator(spec *runtimespec.Spec) generator {
	g := generate.NewFromSpec(spec)
	if goruntime.GOOS == "windows" && spec.Linux != nil {
		// For Windows LCOW we do not want host specific validation
		g.HostSpecific = false
	} else {
		g.HostSpecific = true
	}
	return newCustomGenerator(g)
}

// generator is a custom generator with some functions overridden
// used by the cri plugin.
// TODO(random-liu): Upstream this fix.
type generator struct {
	generate.Generator
	envCache map[string]int
}

func newCustomGenerator(g generate.Generator) generator {
	cg := generator{
		Generator: g,
		envCache:  make(map[string]int),
	}
	if g.Config != nil && g.Config.Process != nil {
		for i, env := range g.Config.Process.Env {
			kv := strings.SplitN(env, "=", 2)
			cg.envCache[kv[0]] = i
		}
	}
	return cg
}

// AddProcessEnv overrides the original AddProcessEnv. It uses
// a map to cache and override envs.
func (g *generator) AddProcessEnv(key, value string) {
	if len(g.envCache) == 0 {
		// Call AddProccessEnv once to initialize the spec.
		g.Generator.AddProcessEnv(key, value)
		g.envCache[key] = 0
		return
	}
	spec := g.Config
	env := fmt.Sprintf("%s=%s", key, value)
	if idx, ok := g.envCache[key]; !ok {
		spec.Process.Env = append(spec.Process.Env, env)
		g.envCache[key] = len(spec.Process.Env) - 1
	} else {
		spec.Process.Env[idx] = env
	}
}

func getPodCNILabels(id string, config *runtime.PodSandboxConfig) map[string]string {
	return map[string]string{
		"K8S_POD_NAMESPACE":          config.GetMetadata().GetNamespace(),
		"K8S_POD_NAME":               config.GetMetadata().GetName(),
		"K8S_POD_INFRA_CONTAINER_ID": id,
		"IgnoreUnknown":              "1",
	}
}

// toRuntimeAuthConfig converts cri plugin auth config to runtime auth config.
func toRuntimeAuthConfig(a criconfig.AuthConfig) *runtime.AuthConfig {
	return &runtime.AuthConfig{
		Username:      a.Username,
		Password:      a.Password,
		Auth:          a.Auth,
		IdentityToken: a.IdentityToken,
	}
}

// parseImageReferences parses a list of arbitrary image references and returns
// the repotags and repodigests
func parseImageReferences(refs []string) ([]string, []string) {
	var tags, digests []string
	for _, ref := range refs {
		parsed, err := docker.ParseAnyReference(ref)
		if err != nil {
			continue
		}
		if _, ok := parsed.(docker.Canonical); ok {
			digests = append(digests, parsed.String())
		} else if _, ok := parsed.(docker.Tagged); ok {
			tags = append(tags, parsed.String())
		}
	}
	return tags, digests
}

// generateRuntimeOptions generates runtime options from cri plugin config.
func generateRuntimeOptions(r criconfig.Runtime, c criconfig.Config) (interface{}, error) {
	if r.Options == nil {
		if r.Type != plugin.RuntimeLinuxV1 {
			return nil, nil
		}
		// This is a legacy config, generate runctypes.RuncOptions.
		return &runctypes.RuncOptions{
			Runtime:       r.Engine,
			RuntimeRoot:   r.Root,
			SystemdCgroup: c.SystemdCgroup,
		}, nil
	}

	if r.Options == nil {
		switch r.Type {
		case plugin.RuntimeLinuxV1:
			// This is a legacy config, generate runctypes.RuncOptions.
			return &runctypes.RuncOptions{
				Runtime:       r.Engine,
				RuntimeRoot:   r.Root,
				SystemdCgroup: c.SystemdCgroup,
			}, nil
		case plugin.RuntimeRunhcsV1:
			return &runhcsoptions.Options{}, nil
		default:
			return nil, nil
		}
	}

	optionsTree, err := toml.TreeFromMap(r.Options)
	if err != nil {
		return nil, err
	}
	options := getRuntimeOptionsType(r.Type)
	if err := optionsTree.Unmarshal(options); err != nil {
		return nil, err
	}
	return options, nil
}

// getRuntimeOptionsType gets empty runtime options by the runtime type name.
func getRuntimeOptionsType(t string) interface{} {
	switch t {
	case plugin.RuntimeRuncV1:
		fallthrough
	case plugin.RuntimeRuncV2:
		return &runcoptions.Options{}
	case plugin.RuntimeLinuxV1:
		return &runctypes.RuncOptions{}
	case runtimeRunhcsV1:
		return &runhcsoptions.Options{}
	default:
		return &runtimeoptions.Options{}
	}
}

// getRuntimeOptions get runtime options from container metadata.
func getRuntimeOptions(c containers.Container) (interface{}, error) {
	if c.Runtime.Options == nil {
		return nil, nil
	}
	opts, err := typeurl.UnmarshalAny(c.Runtime.Options)
	if err != nil {
		return nil, err
	}
	return opts, nil
}

const (
	// unknownExitCode is the exit code when exit reason is unknown.
	unknownExitCode = 255
	// unknownExitReason is the exit reason when exit reason is unknown.
	unknownExitReason = "Unknown"
)

// unknownContainerStatus returns the default container status when its status is unknown.
func unknownContainerStatus() containerstore.Status {
	return containerstore.Status{
		CreatedAt:  0,
		StartedAt:  0,
		FinishedAt: 0,
		ExitCode:   unknownExitCode,
		Reason:     unknownExitReason,
		Unknown:    true,
	}
}

// unknownSandboxStatus returns the default sandbox status when its status is unknown.
func unknownSandboxStatus() sandboxstore.Status {
	return sandboxstore.Status{
		State: sandboxstore.StateUnknown,
	}
}

// getPassthroughAnnotations filters requested pod annotations by comparing
// against permitted annotations for the given runtime.
func getPassthroughAnnotations(podAnnotations map[string]string,
	runtimePodAnnotations []string) (passthroughAnnotations map[string]string) {
	passthroughAnnotations = make(map[string]string)

	for podAnnotationKey, podAnnotationValue := range podAnnotations {
		for _, pattern := range runtimePodAnnotations {
			// Use path.Match instead of filepath.Match here.
			// filepath.Match treated `\\` as path separator
			// on windows, which is not what we want.
			if ok, _ := path.Match(pattern, podAnnotationKey); ok {
				passthroughAnnotations[podAnnotationKey] = podAnnotationValue
			}
		}
	}
	return passthroughAnnotations
}
