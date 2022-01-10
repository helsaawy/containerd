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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/containerd/containerd/log"
	cni "github.com/containerd/go-cni"
	"github.com/containerd/typeurl"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"

	"github.com/containerd/cri/pkg/annotations"
	sandboxstore "github.com/containerd/cri/pkg/store/sandbox"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

func init() {
	typeurl.Register(&sandboxstore.Metadata{},
		"github.com/containerd/cri/pkg/store/sandbox", "Metadata")
}

// parseDNSOptions parse DNS options into resolv.conf format content,
// if none option is specified, will return empty with no error.
func parseDNSOptions(servers, searches, options []string) (string, error) {
	resolvContent := ""

	if len(searches) > maxDNSSearches {
		return "", errors.New("DNSOption.Searches has more than 6 domains")
	}

	if len(searches) > 0 {
		resolvContent += fmt.Sprintf("search %s\n", strings.Join(searches, " "))
	}

	if len(servers) > 0 {
		resolvContent += fmt.Sprintf("nameserver %s\n", strings.Join(servers, "\nnameserver "))
	}

	if len(options) > 0 {
		resolvContent += fmt.Sprintf("options %s\n", strings.Join(options, " "))
	}

	return resolvContent, nil
}

// setupPod setups up the network for a pod
func (c *criService) setupPod(ctx context.Context, id string, path string, config *runtime.PodSandboxConfig) (string, *cni.CNIResult, error) {
	if c.netPlugin == nil {
		return "", nil, errors.New("cni config not initialized")
	}

	labels := getPodCNILabels(id, config)
	result, err := c.netPlugin.Setup(id,
		path,
		cni.WithLabels(labels),
		cni.WithCapabilityPortMap(toCNIPortMappings(config.GetPortMappings())),
		cni.WithCapability("dns", toCNIDNS(config.GetDnsConfig())))
	if err != nil {
		return "", nil, err
	}
	logDebugCNIResult(ctx, id, result)
	// Check if the default interface has IP config
	if configs, ok := result.Interfaces[defaultIfName]; ok && len(configs.IPConfigs) > 0 {
		return selectPodIP(configs.IPConfigs), result, nil
	}
	// If it comes here then the result was invalid so destroy the pod network and return error
	if err := c.teardownPod(id, path, config); err != nil {
		log.G(ctx).WithError(err).Errorf("Failed to destroy network for sandbox %q", id)
	}
	return "", result, errors.Errorf("failed to find network info for sandbox %q", id)
}

// toCNIPortMappings converts CRI port mappings to CNI.
func toCNIPortMappings(criPortMappings []*runtime.PortMapping) []cni.PortMapping {
	var portMappings []cni.PortMapping
	for _, mapping := range criPortMappings {
		if mapping.HostPort <= 0 {
			continue
		}
		portMappings = append(portMappings, cni.PortMapping{
			HostPort:      mapping.HostPort,
			ContainerPort: mapping.ContainerPort,
			Protocol:      strings.ToLower(mapping.Protocol.String()),
			HostIP:        mapping.HostIp,
		})
	}
	return portMappings
}

// https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/dockershim/network/cni/cni.go#L104
type RuntimeDNSConfig struct {
	Servers  []string `json:"servers,omitempty"`
	Searches []string `json:"searches,omitempty"`
	Options  []string `json:"options,omitempty"`
}

// toCNIDNS converts CRI DnsConfig to CNI.
func toCNIDNS(criDnsConfig *runtime.DNSConfig) RuntimeDNSConfig {
	if criDnsConfig == nil {
		return RuntimeDNSConfig{}
	}
	var dns = RuntimeDNSConfig{
		Servers: criDnsConfig.Servers,
		// criDnsConfig does not have a Domain Field
		Searches: criDnsConfig.Searches,
		Options:  criDnsConfig.Options,
	}
	return dns
}

// selectPodIP select an ip from the ip list. It prefers ipv4 more than ipv6.
func selectPodIP(ipConfigs []*cni.IPConfig) string {
	for _, c := range ipConfigs {
		if c.IP.To4() != nil {
			return c.IP.String()
		}
	}
	return ipConfigs[0].IP.String()
}

// untrustedWorkload returns true if the sandbox contains untrusted workload.
func untrustedWorkload(config *runtime.PodSandboxConfig) bool {
	return config.GetAnnotations()[annotations.UntrustedWorkload] == "true"
}

// hostAccessingSandbox returns true if the sandbox configuration
// requires additional host access for the sandbox.
func hostAccessingSandbox(config *runtime.PodSandboxConfig) bool {
	securityContext := config.GetLinux().GetSecurityContext()

	namespaceOptions := securityContext.GetNamespaceOptions()
	if namespaceOptions.GetNetwork() == runtime.NamespaceMode_NODE ||
		namespaceOptions.GetPid() == runtime.NamespaceMode_NODE ||
		namespaceOptions.GetIpc() == runtime.NamespaceMode_NODE {
		return true
	}

	return false
}

func logDebugCNIResult(ctx context.Context, sandboxID string, result *cni.CNIResult) {
	if logrus.GetLevel() < logrus.DebugLevel {
		return
	}
	cniResult, err := json.Marshal(result)
	if err != nil {
		log.G(ctx).WithError(err).Errorf("Failed to marshal CNI result for sandbox %q: %v", sandboxID, err)
		return
	}
	log.G(ctx).Debugf("cni result for sandbox %q: %s", sandboxID, string(cniResult))
}
