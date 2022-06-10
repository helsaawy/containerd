//go:build windows

package payload

import (
	"github.com/containerd/typeurl"
	"github.com/gogo/protobuf/types"
)

func init() {
	typeurl.Register(&WCLayerImportOptions{},
		"github.com/Microsoft/hcsshim/cmd/differ/payload", "WCLayerImportOptions")
}

type WCLayerImportOptions struct {
	RootPath string
	Parents  []string
}

var _ Payload = &WCLayerImportOptions{}

func (p *WCLayerImportOptions) ToAny() (*types.Any, error) {
	return toAny(p)
}

func (p *WCLayerImportOptions) FromAny(a *types.Any) error {
	return fromAny(p, a)
}

func (p *WCLayerImportOptions) Files() []string {
	return append(p.Parents, p.RootPath)
}

// func (p *WCLayerImportOptions) ToAny() (*types.Any, error) {
// 	a, err := typeurl.MarshalAny(p)
// 	if err != nil {
// 		return nil, fmt.Errorf("failed to marshal Tar2Ext4Options: %w", err)
// 	}
// 	return a, nil
// }

// func (p *WCLayerImportOptions) FromAny(a *types.Any) error {
// 	v, err := typeurl.UnmarshalAny(a)
// 	if err != nil || v == nil {
// 		return fmt.Errorf("unmarshal WCLayerImportOptions: %w", err)
// 	}

// 	pp, ok := v.(*WCLayerImportOptions)
// 	if !ok {
// 		return fmt.Errorf("payload type is %T, not WCLayerImportOptions: %w", v, errdefs.ErrInvalidArgument)
// 	}
// 	*p = *pp
// 	return nil
// }
