// This package defines the stream processor payloads to be provided by containerd.
package payload

import (
	"fmt"

	"github.com/containerd/typeurl"
	"github.com/gogo/protobuf/types"
)

type Payload interface {
	FromAny(a *types.Any) error
	ToAny() (*types.Any, error)
	Files() []string
}

// default implementations
func toAny(o interface{}) (*types.Any, error) {
	a, err := typeurl.MarshalAny(o)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal %T: %w", o, err)
	}
	return a, nil
}

func fromAny(o interface{}, a *types.Any) error {
	err := typeurl.UnmarshalTo(a, o)
	if err != nil {
		return fmt.Errorf("unmarshal %T: %w", o, err)
	}
	return nil
}

// func init() {
// 	typeurl.Register(&DifferPayload{},
// 		"github.com/Microsoft/hcsshim/cmd/differ/payload", "DifferOptions")
// }

// type DifferPayload struct {
// 	Files       []string
// 	ExecPayload *types.Any
// }

// var _ Payload = &DifferPayload{}

// func (p *DifferPayload) ToAny() (*types.Any, error) {
// 	return toAny(p)
// }

// func (p *DifferPayload) FromAny(a *types.Any) error {
// 	return fromAny(p, a)
// }

// func (p *DifferPayload) AddExecPayload(ep Payload) (err error) {
// 	p.ExecPayload, err = ep.ToAny()
// 	return err
// }
