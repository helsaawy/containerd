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
	"syscall"
	"time"

	eventtypes "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/log"
	cni "github.com/containerd/go-cni"
	"github.com/pkg/errors"
	"golang.org/x/net/context"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"

	ctrdutil "github.com/containerd/cri/pkg/containerd/util"
	sandboxstore "github.com/containerd/cri/pkg/store/sandbox"
)

// StopPodSandbox stops the sandbox. If there are any running containers in the
// sandbox, they should be forcibly terminated.
func (c *criService) StopPodSandbox(ctx context.Context, r *runtime.StopPodSandboxRequest) (*runtime.StopPodSandboxResponse, error) {
	sandbox, err := c.sandboxStore.Get(r.GetPodSandboxId())
	if err != nil {
		return nil, errors.Wrapf(err, "an error occurred when try to find sandbox %q",
			r.GetPodSandboxId())
	}

	if err := c.stopPodSandbox(ctx, sandbox); err != nil {
		return nil, err
	}

	return &runtime.StopPodSandboxResponse{}, nil
}

func (c *criService) stopPodSandbox(ctx context.Context, sandbox sandboxstore.Sandbox) error {
	// Use the full sandbox id.
	id := sandbox.ID

	// Stop all containers inside the sandbox. This terminates the container forcibly,
	// and container may still be created, so production should not rely on this behavior.
	// TODO(random-liu): Introduce a state in sandbox to avoid future container creation.
	containers := c.containerStore.List()
	for _, container := range containers {
		if container.SandboxID != id {
			continue
		}
		// Forcibly stop the container. Do not use `StopContainer`, because it introduces a race
		// if a container is removed after list.
		if err := c.stopContainer(ctx, container, 0); err != nil {
			return errors.Wrapf(err, "failed to stop container %q", container.ID)
		}
	}

	if err := c.unmountSandboxFiles(id, sandbox.Config); err != nil {
		return errors.Wrap(err, "failed to unmount sandbox files")
	}

	// Only stop sandbox container when it's running or unknown.
	state := sandbox.Status.Get().State
	if state == sandboxstore.StateReady || state == sandboxstore.StateUnknown {
		if err := c.stopSandboxContainer(ctx, sandbox); err != nil {
			return errors.Wrapf(err, "failed to stop sandbox container %q in %q state", id, state)
		}
	}

	return c.doStopPodSandbox(ctx, id, sandbox)
}

// stopSandboxContainer kills the sandbox container.
// `task.Delete` is not called here because it will be called when
// the event monitor handles the `TaskExit` event.
func (c *criService) stopSandboxContainer(ctx context.Context, sandbox sandboxstore.Sandbox) error {
	id := sandbox.ID
	container := sandbox.Container
	state := sandbox.Status.Get().State
	task, err := container.Task(ctx, nil)
	if err != nil {
		if !errdefs.IsNotFound(err) {
			return errors.Wrap(err, "failed to get sandbox container")
		}
		// Don't return for unknown state, some cleanup needs to be done.
		if state == sandboxstore.StateUnknown || state == sandboxstore.StateReady {
			// For the StateReady case we've somehow ended up in a state where the task is gone but the sandbox is still in a
			// ready state. If the task exit event was missed from events.handleSandboxExit this is the likely culprit but a repro of
			// this is hard to pull off. Even in the event of a shim crash task.Wait would return and update the status,
			// so if this condition is hit it's a myriad of strange behavior probably related to containerd restart quirks.
			// Simply reuse the logic if the state is unknown to update the status to NotReady so remove goes smoothly.
			if state == sandboxstore.StateReady {
				log.G(ctx).Warn("Sandbox container state is `Ready` but the task can't be found for the container")
			}
			return cleanupUnknownSandbox(ctx, id, sandbox)
		}
		return nil
	}

	// Handle unknown state.
	// The cleanup logic is the same with container unknown state.
	if state == sandboxstore.StateUnknown {
		// Start an exit handler for containers in unknown state.
		waitCtx, waitCancel := context.WithCancel(ctrdutil.NamespacedContext())
		defer waitCancel()
		exitCh, err := task.Wait(waitCtx)
		if err != nil {
			if !errdefs.IsNotFound(err) {
				return errors.Wrap(err, "failed to wait for task")
			}
			return cleanupUnknownSandbox(ctx, id, sandbox)
		}

		exitCtx, exitCancel := context.WithCancel(context.Background())
		stopCh := c.eventMonitor.startExitMonitor(exitCtx, id, task.Pid(), exitCh)
		defer func() {
			exitCancel()
			// This ensures that exit monitor is stopped before
			// `Wait` is cancelled, so no exit event is generated
			// because of the `Wait` cancellation.
			<-stopCh
		}()
	}

	// Kill the sandbox container.
	if err = task.Kill(ctx, syscall.SIGKILL); err != nil && !errdefs.IsNotFound(err) {
		return errors.Wrap(err, "failed to kill sandbox container")
	}

	return c.waitSandboxStop(ctx, sandbox)
}

// waitSandboxStop waits for sandbox to be stopped until context is cancelled or
// the context deadline is exceeded.
func (c *criService) waitSandboxStop(ctx context.Context, sandbox sandboxstore.Sandbox) error {
	select {
	case <-ctx.Done():
		return errors.Wrapf(ctx.Err(), "wait sandbox container %q", sandbox.ID)
	case <-sandbox.Stopped():
		return nil
	}
}

// teardownPod removes the network from the pod
func (c *criService) teardownPod(id string, path string, config *runtime.PodSandboxConfig) error {
	if c.netPlugin == nil {
		return errors.New("cni config not initialized")
	}

	labels := getPodCNILabels(id, config)
	return c.netPlugin.Remove(id,
		path,
		cni.WithLabels(labels),
		cni.WithCapabilityPortMap(toCNIPortMappings(config.GetPortMappings())),
		cni.WithCapability("dns", toCNIDNS(config.GetDnsConfig())))
}

// cleanupUnknownSandbox cleanup stopped sandbox in unknown state.
func cleanupUnknownSandbox(ctx context.Context, id string, sandbox sandboxstore.Sandbox) error {
	// Reuse handleSandboxExit to do the cleanup.
	return handleSandboxExit(ctx, &eventtypes.TaskExit{
		ContainerID: id,
		ID:          id,
		Pid:         0,
		ExitStatus:  unknownExitCode,
		ExitedAt:    time.Now(),
	}, sandbox)
}
