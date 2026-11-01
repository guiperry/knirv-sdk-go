package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// The module's one import, knirv_host.http_request. It only moves bytes: the
// Rust core builds the request and owns retries, failover and error mapping.
// Wire format: core/src/http_transport.rs.

// httpClient carries the requests; tests replace its transport.
var httpClient = &http.Client{}

type hostRequest struct {
	Method     string            `json:"method"`
	URL        string            `json:"url"`
	Headers    map[string]string `json:"headers"`
	BodyBase64 string            `json:"body_base64"`
	TimeoutMS  uint64            `json:"timeout_ms"`
}

type hostError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type hostResponse struct {
	Status     int               `json:"status,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	BodyBase64 string            `json:"body_base64,omitempty"`
	Error      *hostError        `json:"error,omitempty"`
}

func instantiateHost(ctx context.Context, rt wazero.Runtime) error {
	_, err := rt.NewHostModuleBuilder("knirv_host").
		NewFunctionBuilder().
		WithGoModuleFunction(api.GoModuleFunc(httpRequest),
			[]api.ValueType{api.ValueTypeI32, api.ValueTypeI32},
			[]api.ValueType{api.ValueTypeI64}).
		Export("http_request").
		Instantiate(ctx)
	return err
}

func httpRequest(ctx context.Context, mod api.Module, stack []uint64) {
	ptr, length := api.DecodeU32(stack[0]), api.DecodeU32(stack[1])
	raw, ok := mod.Memory().Read(ptr, length)
	var resp hostResponse
	if !ok {
		resp.Error = &hostError{Kind: "other", Message: "request is outside module memory"}
	} else {
		resp = roundTrip(ctx, append([]byte(nil), raw...))
	}
	out, _ := json.Marshal(resp)
	stack[0] = writeToModule(ctx, mod, out)
}

// writeToModule copies b into memory from the module's knirv_alloc and returns
// (ptr<<32)|len; the module frees it. Zero means the allocation failed.
func writeToModule(ctx context.Context, mod api.Module, b []byte) uint64 {
	res, err := mod.ExportedFunction("knirv_alloc").Call(ctx, uint64(len(b)))
	if err != nil || !mod.Memory().Write(uint32(res[0]), b) {
		return 0
	}
	return res[0]<<32 | uint64(len(b))
}

func roundTrip(ctx context.Context, raw []byte) hostResponse {
	var in hostRequest
	if err := json.Unmarshal(raw, &in); err != nil {
		return hostResponse{Error: &hostError{Kind: "other", Message: "bad request: " + err.Error()}}
	}
	body, err := base64.StdEncoding.DecodeString(in.BodyBase64)
	if err != nil {
		return hostResponse{Error: &hostError{Kind: "other", Message: "bad body: " + err.Error()}}
	}
	// The deadline is the core's timeout_ms; the caller's context can still
	// abort sooner, and either one cancels the request in flight.
	if in.TimeoutMS > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(in.TimeoutMS)*time.Millisecond)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(ctx, in.Method, in.URL, bytes.NewReader(body))
	if err != nil {
		return hostResponse{Error: &hostError{Kind: "other", Message: err.Error()}}
	}
	for k, v := range in.Headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return hostResponse{Error: &hostError{Kind: classify(ctx, err), Message: err.Error()}}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return hostResponse{Error: &hostError{Kind: classify(ctx, err), Message: err.Error()}}
	}
	headers := make(map[string]string, len(resp.Header))
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}
	return hostResponse{Status: resp.StatusCode, Headers: headers, BodyBase64: base64.StdEncoding.EncodeToString(data)}
}

func classify(ctx context.Context, err error) string {
	var (
		dns     *net.DNSError
		unknown x509.UnknownAuthorityError
		invalid x509.CertificateInvalidError
		host    x509.HostnameError
		record  tls.RecordHeaderError
	)
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled):
		return "aborted"
	case errors.As(err, &dns):
		return "dns"
	case errors.As(err, &unknown), errors.As(err, &invalid), errors.As(err, &host), errors.As(err, &record):
		return "tls"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	}
	return "other"
}
