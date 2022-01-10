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
	gocontext "context"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	"github.com/containerd/typeurl"
	runtimespec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"

	ctrdutil "github.com/containerd/cri/pkg/containerd/util"
	"github.com/containerd/cri/pkg/store"
	containerstore "github.com/containerd/cri/pkg/store/container"
	"github.com/containerd/cri/pkg/store/sandbox"
	sandboxstore "github.com/containerd/cri/pkg/store/sandbox"
	"github.com/containerd/cri/pkg/util"
)

// UpdateContainerResources updates ContainerConfig of the container.
func (c *criService) UpdateContainerResources(ctx context.Context, r *runtime.UpdateContainerResourcesRequest) (retRes *runtime.UpdateContainerResourcesResponse, retErr error) {
	if err := c.genericUpdateContainerResources(ctx, r.GetContainerId(), r); err != nil {
		return nil, err
	}
	return &runtime.UpdateContainerResourcesResponse{}, nil
}

// genericUpdateContainerResources is a helper function for updating container resources for
// windows and linux containers
func (c *criService) genericUpdateContainerResources(ctx context.Context, id string, r *runtime.UpdateContainerResourcesRequest) (retErr error) {
	// Update resources in status update transaction, so that:
	// 1) There won't be race condition with container start.
	// 2) There won't be concurrent resource update to the same container.
	cntr, err := c.containerStore.Get(id)
	if err == nil {
		if err := cntr.Status.Update(func(status containerstore.Status) (containerstore.Status, error) {
			id := cntr.ID
			// Do not update the container when there is a removal in progress.
			if status.Removing {
				return status, errors.Errorf("container %q is in removing state", id)
			}

			// Update container spec. If the container is not started yet, updating
			// spec makes sure that the resource limits are correct when start;
			// if the container is already started, updating spec is still required,
			// the spec will become our source of truth for resource limits.
			return status, c.updateContainerResources(ctx, cntr.Container, r)
		}); err != nil {
			return errors.Wrap(err, "failed to update resources")
		}
		return nil
	} else if err == store.ErrNotExist {
		sndbx, err := c.sandboxStore.Get(id)
		if err != nil {
			return errors.Wrap(err, "failed to find container or sandbox")
		}
		if err := sndbx.Status.Update(func(status sandboxstore.Status) (sandboxstore.Status, error) {
			id := cntr.ID
			if status.State == sandbox.StateUnknown || status.State == sandbox.StateNotReady {
				return status, errors.Errorf("sandbox %q must be running to update resources, instead has state %d", id, status.State)
			}

			return status, c.updateContainerResources(ctx, sndbx.Container, r)
		}); err != nil {
			return errors.Wrap(err, "failed to update resources")
		}
		return nil
	}

	return errors.Wrap(err, "failed to find container")
}

func (c *criService) updateContainerResources(ctx context.Context,
	cntr containerd.Container,
	request *runtime.UpdateContainerResourcesRequest) (retErr error) {

	oldSpec, err := cntr.Spec(ctx)
	if err != nil {
		return errors.Wrap(err, "failed to get container spec")
	}
	newSpec, newResources, err := createUpdatedSpec(cntr, oldSpec, request)
	if err != nil {
		return err
	}

	if err := updateContainerSpec(ctx, cntr, newSpec); err != nil {
		return err
	}
	defer func() {
		if retErr != nil {
			deferCtx, deferCancel := ctrdutil.DeferContext()
			defer deferCancel()
			// Reset spec on error.
			if err := updateContainerSpec(deferCtx, cntr, oldSpec); err != nil {
				log.G(ctx).WithError(err).Errorf("Failed to update spec %+v for container %q", oldSpec, cntr.ID())
			}
		}
	}()

	return updateContainerTask(ctx, cntr, newResources, request.Annotations)
}

// createUpdatedSpec creates the updated spec for the given type of container resources requested.
// Returns the new spec and the new resources requested.
func createUpdatedSpec(cntr containerd.Container, oldSpec *runtimespec.Spec, request *runtime.UpdateContainerResourcesRequest) (*runtimespec.Spec, interface{}, error) {
	var (
		err          error
		newSpec      *runtimespec.Spec
		newResources interface{}
	)

	if request.GetLinux() != nil {
		newSpec, err = updateOCILinuxResource(oldSpec, request.GetLinux())
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to update resource in spec")
		}
		newResources = newSpec.Linux.Resources
	} else if request.GetWindows() != nil {
		newSpec, err = updateOCIWindowsResource(oldSpec, request.GetWindows())
		if err != nil {
			return nil, nil, errors.Wrap(err, "failed to update resource in spec")
		}
		newResources = newSpec.Windows.Resources
	}
	return newSpec, newResources, nil
}

// updateContainerSpec makes the call to the containerd container to update the spec
func updateContainerSpec(ctx context.Context, cntr containerd.Container, spec *runtimespec.Spec) error {
	any, err := typeurl.MarshalAny(spec)
	if err != nil {
		return errors.Wrapf(err, "failed to marshal spec %+v", spec)
	}
	if err := cntr.Update(ctx, func(ctx gocontext.Context, client *containerd.Client, c *containers.Container) error {
		c.Spec = any
		return nil
	}); err != nil {
		return errors.Wrap(err, "failed to update container spec")
	}
	return nil
}

// updateContainerTask sends the Update request to the task with the requested resources and annotations to handle
func updateContainerTask(ctx context.Context, cntr containerd.Container, resources interface{}, annotations map[string]string) error {
	task, err := cntr.Task(ctx, nil)
	if err != nil {
		if errdefs.IsNotFound(err) {
			// Task exited already.
			return nil
		}
		return errors.Wrap(err, "failed to get task")
	}
	if err := task.Update(ctx, containerd.WithResources(resources), containerd.WithAnnotations(annotations)); err != nil {
		if errdefs.IsNotFound(err) {
			// Task exited already.
			return nil
		}
		return errors.Wrap(err, "failed to update task resources")
	}
	return nil
}

// updateOCILinuxResource creates an updated container spec with linux resources in `new`.
func updateOCILinuxResource(spec *runtimespec.Spec, new *runtime.LinuxContainerResources) (*runtimespec.Spec, error) {
	// Copy to make sure old spec is not changed.
	var cloned runtimespec.Spec
	if err := util.DeepCopy(&cloned, spec); err != nil {
		return nil, errors.Wrap(err, "failed to deep copy")
	}
	g := newSpecGenerator(&cloned)

	if new.GetCpuPeriod() != 0 {
		g.SetLinuxResourcesCPUPeriod(uint64(new.GetCpuPeriod()))
	}
	if new.GetCpuQuota() != 0 {
		g.SetLinuxResourcesCPUQuota(new.GetCpuQuota())
	}
	if new.GetCpuShares() != 0 {
		g.SetLinuxResourcesCPUShares(uint64(new.GetCpuShares()))
	}
	if new.GetMemoryLimitInBytes() != 0 {
		g.SetLinuxResourcesMemoryLimit(new.GetMemoryLimitInBytes())
	}
	// OOMScore is not updatable.
	if new.GetCpusetCpus() != "" {
		g.SetLinuxResourcesCPUCpus(new.GetCpusetCpus())
	}
	if new.GetCpusetMems() != "" {
		g.SetLinuxResourcesCPUMems(new.GetCpusetMems())
	}

	return g.Config, nil
}

// updateOCIWindowsResource creates an updated container spec with windows resources in `new`.
func updateOCIWindowsResource(spec *runtimespec.Spec, new *runtime.WindowsContainerResources) (*runtimespec.Spec, error) {
	// Copy to make sure old spec is not changed.
	var cloned runtimespec.Spec
	if err := util.DeepCopy(&cloned, spec); err != nil {
		return nil, errors.Wrap(err, "failed to deep copy")
	}
	g := newSpecGenerator(&cloned)
	cpuResources := runtimespec.WindowsCPUResources{}

	if new.GetCpuShares() != 0 {
		shares := uint16(new.GetCpuShares())
		cpuResources.Shares = &shares
	}
	if new.GetCpuCount() != 0 {
		count := uint64(new.GetCpuCount())
		cpuResources.Count = &count
	}
	if new.GetCpuMaximum() != 0 {
		max := uint16(new.GetCpuMaximum())
		cpuResources.Maximum = &max
	}

	if (cpuResources != runtimespec.WindowsCPUResources{}) {
		// cpu resources have new requested limit(s), set on new spec
		g.SetWindowsResourcesCPU(cpuResources)
	}
	if new.GetMemoryLimitInBytes() != 0 {
		g.SetWindowsResourcesMemoryLimit(uint64(new.GetMemoryLimitInBytes()))
	}

	return g.Config, nil
}
