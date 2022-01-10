// +build windows

package io

import "github.com/containerd/containerd/cio"

// WithBinaryFIFOs specifies binary fifos for the container io
func WithBinaryFIFOs(path string) ContainerIOOpts {
	return func(c *ContainerIO) error {
		fifos := &cio.FIFOSet{
			Config: cio.Config{
				Stderr:   path,
				Stdout:   path,
			},
		}
		c.fifos = fifos
		return nil
	}
}
