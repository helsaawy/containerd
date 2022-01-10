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
	runhcsstats "github.com/Microsoft/hcsshim/cmd/containerd-shim-runhcs-v1/stats"
	"github.com/containerd/containerd/api/types"
	containerstore "github.com/containerd/cri/pkg/store/container"
	sandboxstore "github.com/containerd/cri/pkg/store/sandbox"
	"github.com/containerd/typeurl"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

func getSingleContainerMetrics(
	stats *runhcsstats.Statistics,
	cs *runtime.ContainerStats,
	timestamp int64,
) {
	if s := stats.GetWindows(); s != nil {
		if s.Processor != nil {
			cs.Cpu = &runtime.CpuUsage{
				Timestamp:            timestamp,
				UsageCoreNanoSeconds: &runtime.UInt64Value{Value: s.Processor.TotalRuntimeNS},
			}
		}
		if s.Memory != nil {
			cs.Memory = &runtime.MemoryUsage{
				Timestamp:       timestamp,
				WorkingSetBytes: &runtime.UInt64Value{Value: s.Memory.MemoryUsagePrivateWorkingSetBytes},
			}
		}
	} else if s := stats.GetLinux(); s != nil {
		if s.CPU != nil && s.CPU.Usage != nil {
			cs.Cpu = &runtime.CpuUsage{
				Timestamp:            timestamp,
				UsageCoreNanoSeconds: &runtime.UInt64Value{Value: s.CPU.Usage.Total},
			}
		}
		if s.Memory != nil {
			cs.Memory = &runtime.MemoryUsage{
				Timestamp:       timestamp,
				WorkingSetBytes: &runtime.UInt64Value{Value: getWorkingSet(s.Memory)},
			}
		}
	}
}

func (c *criService) getContainerMetrics(
	meta containerstore.Metadata,
	stats *types.Metric,
) (*runtime.ContainerStats, error) {
	var cs runtime.ContainerStats
	var usedBytes, inodesUsed uint64
	sn, err := c.snapshotStore.Get(meta.ID)
	// If snapshotstore doesn't have cached snapshot information
	// set WritableLayer usage to zero
	if err == nil {
		usedBytes = sn.Size
		inodesUsed = sn.Inodes
	}
	cs.WritableLayer = &runtime.FilesystemUsage{
		Timestamp: sn.Timestamp,
		FsId: &runtime.FilesystemIdentifier{
			Mountpoint: c.imageFSPath,
		},
		UsedBytes:  &runtime.UInt64Value{Value: usedBytes},
		InodesUsed: &runtime.UInt64Value{Value: inodesUsed},
	}
	cs.Attributes = &runtime.ContainerAttributes{
		Id:          meta.ID,
		Metadata:    meta.Config.GetMetadata(),
		Labels:      meta.Config.GetLabels(),
		Annotations: meta.Config.GetAnnotations(),
	}

	if stats != nil {
		v, err := typeurl.UnmarshalAny(stats.Data)
		if err != nil {
			return nil, err
		}
		if containerStats, ok := v.(*runhcsstats.Statistics); ok {
			timestamp := stats.Timestamp.UnixNano()
			getSingleContainerMetrics(containerStats, &cs, timestamp)
		}
	}
	return &cs, nil
}

func (c *criService) getSandboxMetrics(
	meta sandboxstore.Metadata,
	stats *types.Metric,
) (*runtime.ContainerStats, error) {
	configMeta := meta.Config.GetMetadata()
	cs := &runtime.ContainerStats{
		Attributes: &runtime.ContainerAttributes{
			Id: meta.ID,
			Metadata: &runtime.ContainerMetadata{
				Name:    configMeta.Name,
				Attempt: configMeta.Attempt,
			},
			Labels:      meta.Config.GetLabels(),
			Annotations: meta.Config.GetAnnotations(),
		},
	}
	if stats != nil {
		v, err := typeurl.UnmarshalAny(stats.Data)
		if err != nil {
			return nil, err
		}
		if s, ok := v.(*runhcsstats.Statistics); ok {
			timestamp := stats.Timestamp.UnixNano()
			// If the pod is process isolated VM will be nil. We have special treatment
			// for hypervisor isolated pod stats as we return the UVMs working set and
			// other metrics instead of the actual sandbox containers.
			if s.VM != nil {
				if s.VM.Processor != nil {
					cs.Cpu = &runtime.CpuUsage{
						Timestamp:            timestamp,
						UsageCoreNanoSeconds: &runtime.UInt64Value{Value: s.VM.Processor.TotalRuntimeNS},
					}
				}
				if s.VM.Memory != nil {
					cs.Memory = &runtime.MemoryUsage{
						Timestamp:       timestamp,
						WorkingSetBytes: &runtime.UInt64Value{Value: s.VM.Memory.WorkingSetBytes},
					}
				}
			} else {
				getSingleContainerMetrics(s, cs, timestamp)
			}
		}
	}
	return cs, nil
}
