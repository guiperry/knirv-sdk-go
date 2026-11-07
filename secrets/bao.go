package secrets

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	knirvsigning "github.com/guiperry/knirv-sdk-go/signing"
)

// BaoProvider reads secrets from a node-local OpenBao over its owner-only unix
// socket. It is the second backend behind the Provider interface (see OpenBao.md
// §4.4); the file backend is FileProvider. Reading and signing go through the
// plugin's HTTP API; the raw identity keys never leave OpenBao, so no service
// process outside `bao` holds them.
type BaoProvider struct {
	socket string
	token  string
	client *http.Client
}

// NewBaoProvider returns the OpenBao-backed Provider. socket is the path to
// bao.sock; token is the bearer token the node obtained through AppRole login
// (Task 2a.5). An empty token fails reads at request time, matching OpenBao's
// auth model — the provider never falls back to the file backend on its own.
func NewBaoProvider(socket, token string) *BaoProvider {
	return &BaoProvider{
		socket: socket,
		token:  token,
		client: newUnixClient(socket),
	}
}

func newUnixClient(socket string) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
		Timeout: 15 * time.Second,
	}
}

// Root reads the root-node KV groups. A node with no root groups returns a
// zero-valued RootSecrets rather than nil, so the dual-read self-check can hash
// it consistently with the file backend.
func (p *BaoProvider) Root(ctx context.Context) (*RootSecrets, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root := &RootSecrets{Path: "bao://" + p.socket}
	var gerr error
	// A genuinely absent group (HTTP 404) is an empty group, not an error. Any
	// other failure (transport, unauthorized, malformed) is returned so the bao
	// backend fails closed instead of assembling fabricated empty secrets.
	load := func(group string) map[string]json.RawMessage {
		m, err := p.kv(ctx, group)
		if err != nil {
			if gerr == nil {
				gerr = err
			}
			return nil
		}
		return m
	}
	cloudflare := load("cloudflare")
	pay := load("payments")
	llm := load("llm")
	auth := load("auth")
	tls := load("tls")
	dev := load("device")
	if gerr != nil {
		return nil, gerr
	}
	root.Cloudflare = cloudflareFromMap(cloudflare)
	root.StripeSecretKey = str(pay, "stripe_secret_key")
	root.StripeWebhookSecret = str(pay, "stripe_webhook_secret")
	root.StripeThinWebhookSecret = str(pay, "stripe_thin_webhook_secret")
	root.StripeProfessionalPriceID = str(pay, "stripe_professional_price_id")
	root.StripeEnterprisePriceID = str(pay, "stripe_enterprise_price_id")
	root.StripeInvestorPriceID = str(pay, "stripe_investor_price_id")
	root.CoinbaseAPIKey = str(pay, "coinbase_api_key")
	root.CoinbaseWebhookSecret = str(pay, "coinbase_webhook_secret")
	root.PaymentProcessorEnabled = boolFromMap(pay, "payment_processor_enabled")
	root.PaymentSuccessURL = str(pay, "payment_success_url")
	root.PaymentCancelURL = str(pay, "payment_cancel_url")
	root.PaymentOnboardingCallbackURL = str(pay, "payment_onboarding_callback_url")
	root.GeminiAPIKey = str(llm, "gemini_api_key")
	root.DeepseekAPIKey = str(llm, "deepseek_api_key")
	root.CerebrasAPIKey = str(llm, "cerebras_api_key")
	root.JWTSecret = str(auth, "jwt_secret")
	root.KNIRVJWTSecret = str(auth, "knirv_jwt_secret")
	root.SMTPPassword = str(auth, "smtp_password")
	root.DefaultGitHubToken = str(auth, "default_github_token")
	root.TLSCert = str(tls, "tls_cert")
	root.TLSKey = str(tls, "tls_key")
	root.DeviceIP = str(dev, "device_ip")
	root.DevicePassword = str(dev, "device_password")
	root.DeviceUsername = str(dev, "device_username")
	return root, nil
}

// Boot reads the bootnode KV groups.
func (p *BaoProvider) Boot(ctx context.Context) (*BootSecrets, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	boot := &BootSecrets{Path: "bao://" + p.socket}
	var gerr error
	load := func(group string) map[string]json.RawMessage {
		m, err := p.kv(ctx, group)
		if err != nil {
			if gerr == nil {
				gerr = err
			}
			return nil
		}
		return m
	}
	cloudflare := load("cloudflare")
	pay := load("payments")
	llm := load("llm")
	auth := load("auth")
	dev := load("device")
	reg := load("registration")
	if gerr != nil {
		return nil, gerr
	}
	boot.Cloudflare = cloudflareFromMap(cloudflare)
	boot.StripeSecretKey = str(pay, "stripe_secret_key")
	boot.DefaultGitHubToken = str(pay, "default_github_token")
	boot.SMTPPassword = str(pay, "smtp_password")
	boot.GeminiAPIKey = str(llm, "gemini_api_key")
	boot.DeepseekAPIKey = str(llm, "deepseek_api_key")
	boot.CerebrasAPIKey = str(llm, "cerebras_api_key")
	boot.JWTSecret = str(auth, "jwt_secret")
	boot.DeviceIP = str(dev, "device_ip")
	boot.DevicePassword = str(dev, "device_password")
	boot.DeviceUsername = str(dev, "device_username")
	boot.RegistrationID = str(reg, "registration_id")
	return boot, nil
}

// Signer returns a RemoteSigner that delegates to the knirv plugin's sign
// endpoints for the named identity (OpenBao.md §4.5). The logical name is
// resolved to its canonical Bao plugin identity by the Rust core
// (secrets.bao_signer_name), which owns the role→identity mapping; Go never
// switches on names itself.
func (p *BaoProvider) Signer(ctx context.Context, name string) (knirvsigning.RemoteSigner, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var resolved struct {
		Name string `json:"name"`
	}
	if err := call("secrets.bao_signer_name", map[string]string{"name": name}, &resolved); err != nil {
		return nil, fmt.Errorf("secrets: resolve bao signer %q: %w", name, err)
	}
	if resolved.Name == "" {
		return nil, fmt.Errorf("secrets: bao signer %q resolved to empty identity", name)
	}
	return &baoSigner{name: resolved.Name, client: p.client, token: p.token}, nil
}

// Health reports the coarse backend state from the socket and seal status.
func (p *BaoProvider) Health(ctx context.Context) Status {
	if _, err := os.Stat(p.socket); err != nil {
		return Status{Backend: "bao", State: StateAbsent, Reason: "bao.sock not found at " + p.socket}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/v1/sys/seal-status", nil)
	if err != nil {
		return Status{Backend: "bao", State: StateDegraded, Reason: err.Error()}
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return Status{Backend: "bao", State: StateDegraded, Reason: err.Error()}
	}
	defer resp.Body.Close()
	var status struct {
		Initialized bool `json:"initialized"`
		Sealed      bool `json:"sealed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return Status{Backend: "bao", State: StateDegraded, Reason: "invalid seal-status response"}
	}
	if !status.Initialized {
		return Status{Backend: "bao", State: StateAbsent, Reason: "OpenBao is not initialized"}
	}
	if status.Sealed {
		return Status{Backend: "bao", State: StateDegraded, Reason: "OpenBao is sealed"}
	}
	return Status{Backend: "bao", State: StateReady}
}

// kv reads one named KV v2 group under knirv-kv/data/node/<group>. A genuinely
// absent group (HTTP 404) is returned as an empty map, not an error; the caller
// treats an optional group as empty. Any other failure — transport error,
// unauthorized (403), malformed response — is returned so the bao backend fails
// closed rather than assembling fabricated empty secrets. The error is bounded
// to method/path/status only; it never carries a body, token, or secret.
func (p *BaoProvider) kv(ctx context.Context, group string) (map[string]json.RawMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	url := "http://localhost/v1/knirv-kv/data/node/" + group
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("secrets: read knirv-kv %s: %w", group, err)
	}
	if p.token != "" {
		req.Header.Set("X-Vault-Token", p.token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("secrets: read knirv-kv %s: transport error", group)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		// The group is genuinely absent; surface it as an empty group.
		return map[string]json.RawMessage{}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("secrets: read knirv-kv %s: http %d", group, resp.StatusCode)
	}
	var out struct {
		Data struct {
			Data map[string]json.RawMessage `json:"data"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("secrets: read knirv-kv %s: invalid response", group)
	}
	return out.Data.Data, nil
}

// RawSign signs a precomputed 32-byte digest with the named identity through the
// plugin's raw compact endpoint, returning a hex 64-byte r||s secp256k1 signature
// (the recovery byte is stripped) — byte-identical to the registry's legacy
// dcrd SignCompact(priv, digest, true)[1:] form. The digest is supplied by the
// caller (typically sha256 of a canonicalized message); the plugin never
// canonicalizes, so the signed bytes match the in-process legacy signer exactly.
// Only allowlisted purposes (failover-identity) are accepted by the plugin, and
// the OpenBao ACL grants the path to the backend/failover AppRole only.
func (p *BaoProvider) RawSign(ctx context.Context, purpose string, digest []byte) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	// Validate against the canonical raw-sign contract (mirror of core
	// secrets.raw_sign_validate) before any transport. The plugin enforces the
	// same contract server-side as the outer gate (OpenBao.md §4.6).
	if err := validateRawSign(purpose, hex.EncodeToString(digest)); err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]string{"digest": hex.EncodeToString(digest)})
	if err != nil {
		return "", fmt.Errorf("secrets: raw sign encode: %w", err)
	}
	url := "http://localhost/v1/knirv/sign/raw/" + purpose
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("secrets: raw sign %s: %w", purpose, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.token != "" {
		req.Header.Set("X-Vault-Token", p.token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("secrets: raw sign %s: %w", purpose, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("secrets: raw sign %s: http %d", purpose, resp.StatusCode)
	}
	var env struct {
		Data struct {
			Signature string `json:"signature"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return "", fmt.Errorf("secrets: raw sign %s: decode: %w", purpose, err)
	}
	if env.Data.Signature == "" {
		return "", fmt.Errorf("secrets: raw sign %s: empty signature", purpose)
	}
	return env.Data.Signature, nil
}

// validatorKVGroup is the OpenBao KV v2 group that holds operator-tunable
// validator settings (OpenBao.md §4.7). It is read-only for the Oracle policy and
// written only by the launcher at first boot / enrollment.
const validatorKVGroup = "validator"

// ValidatorSettings reads node/validator and applies the lowering-only rule: the
// KV values may reduce, never raise, the privilege the role resolver (8.1) derived.
// resolverMax is the ceiling the resolver produced (e.g. "active", "standby",
// "off"); the returned OracleModeMax never exceeds it. When the group is absent the
// resolver-derived ceiling is returned unchanged.
func (p *BaoProvider) ValidatorSettings(ctx context.Context, resolverMax string) (*ValidatorSettingsResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m, err := p.kv(ctx, validatorKVGroup)
	if err != nil {
		return nil, err
	}
	res := &ValidatorSettingsResult{
		Enabled:       true,
		OracleModeMax: resolverMax,
	}
	if raw, ok := m["enabled"]; ok {
		// Only an explicit false lowers; absence defaults to enabled.
		var enabled bool
		if json.Unmarshal(raw, &enabled) == nil {
			res.Enabled = enabled
		}
	}
	if raw, ok := m["oracle_mode_max"]; ok {
		var mode string
		if json.Unmarshal(raw, &mode) == nil && mode != "" {
			// Lowering-only: keep the KV value only when it does not exceed the
			// resolver ceiling. A higher value is ignored (the resolver wins).
			if oracleModeRank(mode) <= oracleModeRank(resolverMax) {
				res.OracleModeMax = mode
			} else {
				// A raise-above-resolver request is a misconfiguration or a stale
				// KV value; name the field and ignore it rather than widening
				// privilege (OpenBao.md §4.7 rule: the resolver is authoritative).
				log.Printf("knirv secrets: ValidatorSettings ignoring oracle_mode_max=%q on node/validator: it would raise privilege above the role-resolver ceiling %q; keeping %q",
					mode, resolverMax, resolverMax)
			}
		}
	}
	if raw, ok := m["replication_sources"]; ok {
		var src []string
		if json.Unmarshal(raw, &src) == nil {
			res.ReplicationSources = src
		}
	}
	res.ReplicationInterval = str(m, "replication_interval")
	if raw, ok := m["max_lag_seq"]; ok {
		var n int
		if json.Unmarshal(raw, &n) == nil {
			res.MaxLagSeq = n
		}
	}
	res.ValidatorID = str(m, "validator_id")
	return res, nil
}

// oracleModeRank orders the Oracle privilege ceiling: higher rank = more privilege.
// An unknown value sorts below everything so it can never widen permissions.
func oracleModeRank(mode string) int {
	switch mode {
	case "active":
		return 2
	case "standby":
		return 1
	case "off":
		return 0
	default:
		return -1
	}
}

func cloudflareFromMap(m map[string]json.RawMessage) Cloudflare {
	return Cloudflare{
		APIToken:           str(m, "api_token"),
		ZoneID:             str(m, "zone_id"),
		AccountID:          str(m, "account_id"),
		MainnetTunnelToken: str(m, "mainnet_tunnel_token"),
		TestnetTunnelToken: str(m, "testnet_tunnel_token"),
		OracleTunnelToken:  str(m, "oracle_tunnel_token"),
	}
}

func str(m map[string]json.RawMessage, key string) string {
	raw, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}

func boolFromMap(m map[string]json.RawMessage, key string) bool {
	raw, ok := m[key]
	if !ok {
		return false
	}
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	return false
}

// baoSigner is the RemoteSigner that delegates signing to the knirv plugin.
type baoSigner struct {
	name   string
	client *http.Client
	token  string
}

// KeyInfo is the public description a plugin key exposes (never the private key).
type KeyInfo struct {
	Address   string `json:"address"`
	PublicKey []byte `json:"public_key"`
}

func (p *BaoProvider) keyInfo(ctx context.Context, purpose string) (KeyInfo, error) {
	url := "http://localhost/v1/knirv/keys/" + purpose
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return KeyInfo{}, err
	}
	if p.token != "" {
		req.Header.Set("X-Vault-Token", p.token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return KeyInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return KeyInfo{}, fmt.Errorf("secrets: read key %s returned HTTP %d", purpose, resp.StatusCode)
	}
	// The plugin returns its payload under OpenBao's standard "data" envelope.
	var env struct {
		Data KeyInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return KeyInfo{}, fmt.Errorf("secrets: decode key %s: %w", purpose, err)
	}
	if env.Data.Address == "" && len(env.Data.PublicKey) == 0 {
		return KeyInfo{}, fmt.Errorf("secrets: key %s returned an empty address and public key", purpose)
	}
	return env.Data, nil
}

// KeyInfo returns the public description (address + compressed public key) of the
// named signing identity from the plugin. It is used by callers that sign through
// Bao but still need the identity's public fields (e.g. the failover control plane).
func (p *BaoProvider) KeyInfo(ctx context.Context, purpose string) (KeyInfo, error) {
	return p.keyInfo(ctx, purpose)
}

func (s *baoSigner) keyInfo(ctx context.Context) (KeyInfo, error) {
	url := "http://localhost/v1/knirv/keys/" + s.name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return KeyInfo{}, err
	}
	if s.token != "" {
		req.Header.Set("X-Vault-Token", s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return KeyInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return KeyInfo{}, fmt.Errorf("secrets: read key %s returned HTTP %d", s.name, resp.StatusCode)
	}
	var env struct {
		Data KeyInfo `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return KeyInfo{}, fmt.Errorf("secrets: decode key %s: %w", s.name, err)
	}
	if env.Data.Address == "" && len(env.Data.PublicKey) == 0 {
		return KeyInfo{}, fmt.Errorf("secrets: key %s returned an empty address and public key", s.name)
	}
	return env.Data, nil
}

func (s *baoSigner) Address() string {
	info, err := s.keyInfo(context.Background())
	if err != nil {
		return ""
	}
	return info.Address
}

func (s *baoSigner) PublicKey() []byte {
	info, err := s.keyInfo(context.Background())
	if err != nil {
		return nil
	}
	return info.PublicKey
}

func (s *baoSigner) sign(ctx context.Context, kind string, body any, into any) error {
	encoded, err := json.Marshal(body)
	if err != nil {
		return err
	}
	url := "http://localhost/v1/knirv/sign/" + kind + "/" + s.name
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.token != "" {
		req.Header.Set("X-Vault-Token", s.token)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("secrets: sign %s/%s returned HTTP %d", kind, s.name, resp.StatusCode)
	}
	// The plugin returns the signed payload under OpenBao's standard "data" envelope.
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return fmt.Errorf("secrets: decode sign %s/%s: %w", kind, s.name, err)
	}
	if len(env.Data) == 0 || string(env.Data) == "null" {
		return fmt.Errorf("secrets: sign %s/%s returned an empty payload", kind, s.name)
	}
	return json.Unmarshal(env.Data, into)
}

func (s *baoSigner) SignDirect(ctx context.Context, req knirvsigning.SignRequest) (knirvsigning.SignedTransaction, error) {
	if err := ctx.Err(); err != nil {
		return knirvsigning.SignedTransaction{}, err
	}
	var out knirvsigning.SignedTransaction
	if err := s.sign(ctx, "direct", req, &out); err != nil {
		return knirvsigning.SignedTransaction{}, err
	}
	return out, nil
}

func (s *baoSigner) SignMessage(ctx context.Context, envelope knirvsigning.MessageEnvelope) (knirvsigning.SignedMessage, error) {
	if err := ctx.Err(); err != nil {
		return knirvsigning.SignedMessage{}, err
	}
	var out knirvsigning.SignedMessage
	if err := s.sign(ctx, "message", envelope, &out); err != nil {
		return knirvsigning.SignedMessage{}, err
	}
	return out, nil
}

// baoReady reports whether the OpenBao at socket is initialized and unsealed,
// using the unauthenticated seal-status endpoint. It is used by backend
// selection to decide whether the bao backend is usable.
func baoReady(socket string) bool {
	client := newUnixClient(socket)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/v1/sys/seal-status", nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	var status struct {
		Initialized bool `json:"initialized"`
		Sealed      bool `json:"sealed"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		return false
	}
	return status.Initialized && !status.Sealed
}
