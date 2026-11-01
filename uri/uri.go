// Package uri is the Go binding for the canonical knirv:// URI grammar. The
// grammar, canonicalisation and ID derivation are implemented once, in the Rust
// core (core/src/uri.rs), and reached through the "uri.*" binding operations.
// This package keeps the Go result types.
package uri

import (
	"context"
	"encoding/json"
	"fmt"

	knirv "github.com/guiperry/knirv-sdk-go"
)

var native = knirv.NewClient()

func call(op string, request, response any) error {
	body, err := json.Marshal(request)
	if err != nil {
		return err
	}
	out, err := native.Execute(context.Background(), op, body)
	if err != nil {
		return err
	}
	return json.Unmarshal(out, response)
}

// Kind classifies a parsed URI.
type Kind string

const (
	KindCanonical      Kind = "canonical"
	KindLegacyDVE      Kind = "legacy_dve"
	KindContentPointer Kind = "content_pointer"
	KindAction         Kind = "action"
	KindInvalid        Kind = "invalid"
)

// ResourceTypes is the routable resource-type registry, read from the core.
var ResourceTypes = func() map[string]struct{} {
	registry := loadRegistry()
	out := make(map[string]struct{}, len(registry.ResourceTypes))
	for _, name := range registry.ResourceTypes {
		out[name] = struct{}{}
	}
	return out
}()

// QueryKeys are the keys the grammar reserves for USD identity and tenancy.
var QueryKeys = loadRegistry().QueryKeys

type registry struct {
	ResourceTypes []string `json:"resource_types"`
	QueryKeys     []string `json:"query_keys"`
}

func loadRegistry() registry {
	var r registry
	if err := call("uri.registry", struct{}{}, &r); err != nil {
		panic(fmt.Sprintf("uri: native core registry unavailable: %v", err))
	}
	return r
}

// LegacyDVE describes one of the three historical DVE URI shapes.
type LegacyDVE struct {
	Form string `json:"form"`
	ID   string `json:"id"`
	Hash string `json:"hash,omitempty"`
	Name string `json:"name,omitempty"`
}

// ContentPointer is the on-chain knirv://network/<kind>_<hash> shape.
type ContentPointer struct {
	Kind string `json:"kind"`
	Hash string `json:"hash"`
}

// Action is a QR-login or signing-approval link.
type Action struct {
	Name      string            `json:"name"`
	Query     map[string]string `json:"query"`
	Canonical string            `json:"canonical"`
}

// Result is the typed outcome of Parse. Kind selects which fields are set.
type Result struct {
	Kind           Kind
	Canonical      string
	ID             string
	ResourceType   string
	SubPath        string
	Query          map[string]string
	LegacyDVE      *LegacyDVE
	ContentPointer *ContentPointer
	Action         *Action
	Reason         string
}

// Valid reports whether the input was understood.
func (r Result) Valid() bool { return r.Kind != KindInvalid && r.Kind != "" }

type wireResult struct {
	Kind           Kind              `json:"kind"`
	Canonical      string            `json:"canonical"`
	ID             string            `json:"id"`
	ResourceType   string            `json:"resource_type"`
	Path           string            `json:"path"`
	Query          map[string]string `json:"query"`
	LegacyDVE      *LegacyDVE        `json:"legacy_dve"`
	ContentPointer *ContentPointer   `json:"content_pointer"`
	Action         *Action           `json:"action"`
	Reason         string            `json:"reason"`
}

// Parse parses raw without ever returning an error: legacy, pointer, and action
// shapes are typed results, and malformed input is KindInvalid with Reason.
func Parse(raw string) Result {
	var w wireResult
	if err := call("uri.parse", map[string]string{"raw": raw}, &w); err != nil {
		return Result{Kind: KindInvalid, Reason: "native URI parser unavailable: " + err.Error()}
	}
	return Result{
		Kind: w.Kind, Canonical: w.Canonical, ID: w.ID, ResourceType: w.ResourceType,
		SubPath: w.Path, Query: w.Query, LegacyDVE: w.LegacyDVE,
		ContentPointer: w.ContentPointer, Action: w.Action, Reason: w.Reason,
	}
}

func id(op, raw string) string {
	var out struct {
		ID string `json:"id"`
	}
	if err := call(op, map[string]string{"raw": raw}, &out); err != nil {
		panic(fmt.Sprintf("uri: native core %s failed: %v", op, err))
	}
	return out.ID
}

// NormalizeID returns raw when it is already a valid ID, else its derived form.
func NormalizeID(raw string) string { return id("uri.normalize_id", raw) }

// DeriveID maps any raw identifier to base32(sha256(raw))[:32], lowercase.
func DeriveID(raw string) string { return id("uri.derive_id", raw) }
