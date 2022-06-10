//go:build windows

package payload

import (
	"github.com/containerd/typeurl"
	"github.com/gogo/protobuf/types"

	"github.com/Microsoft/hcsshim/ext4/tar2ext4"
)

func init() {
	typeurl.Register(&Tar2Ext4Options{},
		"github.com/Microsoft/hcsshim/cmd/differ/payload", "Tar2Ext4Options")
}

// need to be able to serialize tar2ext4 options across pipe
type Tar2Ext4Options struct {
	ConvertWhiteout bool
	AppendVhdFooter bool
	AppendDMVerity  bool
	InlineData      bool
	MaximumDiskSize int64

	VHDPath string
}

var _ Payload = &Tar2Ext4Options{}

func (p *Tar2Ext4Options) ToAny() (*types.Any, error) {
	return toAny(p)
}

func (p *Tar2Ext4Options) FromAny(a *types.Any) error {
	return fromAny(p, a)
}

func (p *Tar2Ext4Options) Files() []string {
	return []string{p.VHDPath}
}

// func (p *Tar2Ext4Options) ToAny() (*types.Any, error) {
// 	a, err := typeurl.MarshalAny(p)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to marshal Tar2Ext4Options: %w", err)
// 	}
// 	return a, nil
// }

// func (p *Tar2Ext4Options) FromAny(a *types.Any) error {
// 	v, err := typeurl.UnmarshalAny(a)
// 	if err != nil || v == nil {
// 		return fmt.Errorf("unmarshal Tar2Ext4Options: %w", err)
// 	}

// 	pp, ok := v.(*Tar2Ext4Options)
// 	if !ok {
// 		return fmt.Errorf("payload type is %T, not Tar2Ext4Options: %w", v, errdefs.ErrInvalidArgument)
// 	}
// 	*p = *pp
// 	return nil
// }

func (p *Tar2Ext4Options) Options() []tar2ext4.Option {
	opts := make([]tar2ext4.Option, 0, 5)
	if p == nil {
		return opts
	}

	if p.ConvertWhiteout {
		opts = append(opts, tar2ext4.ConvertWhiteout)
	}
	if p.AppendVhdFooter {
		opts = append(opts, tar2ext4.AppendVhdFooter)
	}
	if p.AppendDMVerity {
		opts = append(opts, tar2ext4.AppendDMVerity)
	}
	if p.InlineData {
		opts = append(opts, tar2ext4.InlineData)
	}
	if p.MaximumDiskSize != 0 {
		opts = append(opts, tar2ext4.MaximumDiskSize(p.MaximumDiskSize))
	}

	return opts
}
