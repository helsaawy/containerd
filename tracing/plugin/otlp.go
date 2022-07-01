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

package plugin

import (
	"context"
	"fmt"
	"io"

	"github.com/containerd/containerd/log"
	"github.com/containerd/containerd/plugin"
	"github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
)

const exporterPlugin = "otlp"

func init() {
	plugin.Register(&plugin.Registration{
		ID:     exporterPlugin,
		Type:   plugin.TracingProcessorPlugin,
		Config: &OTLPConfig{},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			// cfg := ic.Config.(*OTLPConfig)
			// if cfg.Endpoint == "" {
			// 	return nil, fmt.Errorf("no OpenTelemetry endpoint: %w", plugin.ErrSkipPlugin)
			// }
			// exp, err := newExporter(ic.Context, cfg)
			// if err != nil {
			// 	return nil, err
			// }
			exp := newExporter()
			return trace.NewBatchSpanProcessor(exp), nil
		},
	})
	plugin.Register(&plugin.Registration{
		ID:       "tracing",
		Type:     plugin.InternalPlugin,
		Requires: []plugin.Type{plugin.TracingProcessorPlugin},
		Config:   &TraceConfig{ServiceName: "containerd", TraceSamplingRatio: 1.0},
		InitFn: func(ic *plugin.InitContext) (interface{}, error) {
			return newTracer(ic)
		},
	})
}

// OTLPConfig holds the configurations for the built-in otlp span processor
type OTLPConfig struct {
	Endpoint string `toml:"endpoint"`
	Protocol string `toml:"protocol"`
	Insecure bool   `toml:"insecure"`
}

// TraceConfig is the common configuration for open telemetry.
type TraceConfig struct {
	ServiceName        string  `toml:"service_name"`
	TraceSamplingRatio float64 `toml:"sampling_ratio"`
}

type closer struct {
	close func() error
}

func (c *closer) Close() error {
	return c.close()
}

type LogrusExporter struct{}

var _ trace.SpanExporter = &LogrusExporter{}

func newExporter() trace.SpanExporter {
	return &LogrusExporter{}
}

func (e *LogrusExporter) ExportSpans(ctx context.Context, spans []trace.ReadOnlySpan) error {
	for _, span := range spans {
		go func(span trace.ReadOnlySpan) {
			entry := log.L.Dup()
			attrs := span.Attributes()
			data := make(logrus.Fields, len(entry.Data)+len(attrs)+10)

			for k, v := range entry.Data {
				data[k] = v
			}
			for _, kv := range attrs {
				if v, err := kv.Value.MarshalJSON(); err == nil {
					data[string(kv.Key)] = string(v)
				}
			}

			sc := span.SpanContext()
			data["name"] = span.Name()
			data["traceID"] = sc.TraceID().String()
			data["SpanID"] = sc.SpanID().String()
			data["ParentSpanID"] = span.Parent().SpanID().String()
			data["StartTime"] = span.StartTime().Format(log.RFC3339NanoFixed)
			data["EndTime"] = span.EndTime().Format(log.RFC3339NanoFixed)
			data["Duration"] = span.EndTime().Sub(span.StartTime())

			level := logrus.InfoLevel
			if st := span.Status(); st.Code != 0 {
				level = logrus.ErrorLevel

				// don't overwrite an existing "error"
				if _, ok := data[logrus.ErrorKey]; !ok {
					data[logrus.ErrorKey] = st.Description
				}
			}

			entry.Data = data
			entry.Time = span.StartTime()
			entry.Log(level, "Span")
		}(span)
	}
	return nil
}

func (e *LogrusExporter) Shutdown(ctx context.Context) error {
	return nil
}

// newTracer configures protocol-agonostic tracing settings such as
// its sampling ratio and returns io.Closer.
//
// Note that this function sets process-wide tracing configuration.
func newTracer(ic *plugin.InitContext) (io.Closer, error) {
	ctx := ic.Context
	config := ic.Config.(*TraceConfig)

	res, err := resource.New(ctx,
		resource.WithAttributes(
			// Service name used to displace traces in backends
			semconv.ServiceNameKey.String(config.ServiceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	opts := []sdktrace.TracerProviderOption{
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(config.TraceSamplingRatio)),
		sdktrace.WithResource(res),
	}

	ls, err := ic.GetByType(plugin.TracingProcessorPlugin)
	if err != nil {
		return nil, fmt.Errorf("failed to get tracing processors: %w", err)
	}

	procs := make([]sdktrace.SpanProcessor, 0, len(ls))
	for id, pctx := range ls {
		p, err := pctx.Instance()
		if err != nil {
			log.G(ctx).WithError(err).Errorf("failed to initialize a tracing processor %q", id)
			continue
		}
		proc := p.(sdktrace.SpanProcessor)
		opts = append(opts, sdktrace.WithSpanProcessor(proc))
		procs = append(procs, proc)
	}

	provider := sdktrace.NewTracerProvider(opts...)

	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	return &closer{close: func() error {
		for _, p := range procs {
			if err := p.Shutdown(ctx); err != nil {
				return err
			}
		}
		return nil
	}}, nil
}
