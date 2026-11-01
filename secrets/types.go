package secrets

import (
	"context"

	knirvsigning "github.com/guiperry/knirv-sdk-go/signing"
)

// State is the coarse health of a secrets backend.
type State string

const (
	StateReady    State = "ready"
	StateDegraded State = "degraded"
	StateAbsent   State = "absent"
)

// Status is returned by Provider.Health. Backend names the concrete
// implementation ("file", "bao") so /health can surface which is in use.
type Status struct {
	Backend string
	State   State
	Reason  string
}

// Cloudflare groups the Cloudflare fields that differ in field number between
// root_key.proto and bootnode_key.proto. Flattening them here means callers
// never index by proto field number again.
type Cloudflare struct {
	APIToken           string `json:"api_token"`
	ZoneID             string `json:"zone_id"`
	AccountID          string `json:"account_id"`
	MainnetTunnelToken string `json:"mainnet_tunnel_token"`
	TestnetTunnelToken string `json:"testnet_tunnel_token"`
	OracleTunnelToken  string `json:"oracle_tunnel_token"`
}

// RootSecrets is the decrypted contents of root.key with named fields.
// Zero-valued fields were not present in the file.
type RootSecrets struct {
	Path string `json:"path"`

	StripeSecretKey       string `json:"stripe_secret_key"`
	StripeWebhookSecret   string `json:"stripe_webhook_secret"`
	CoinbaseAPIKey        string `json:"coinbase_api_key"`
	CoinbaseWebhookSecret string `json:"coinbase_webhook_secret"`
	RootPrivateKeyHex     string `json:"root_private_key_hex"`

	JWTSecret      string `json:"jwt_secret"`
	KNIRVJWTSecret string `json:"knirv_jwt_secret"`
	GeminiAPIKey   string `json:"gemini_api_key"`
	DeepseekAPIKey string `json:"deepseek_api_key"`
	CerebrasAPIKey string `json:"cerebras_api_key"`
	TLSCert        string `json:"tls_cert"`
	TLSKey         string `json:"tls_key"`

	Cloudflare Cloudflare `json:"cloudflare"`

	SMTPPassword       string `json:"smtp_password"`
	DefaultGitHubToken string `json:"default_github_token"`

	DeviceIP       string `json:"device_ip"`
	DevicePassword string `json:"device_password"`
	DeviceUsername string `json:"device_username"`

	PaymentProcessorEnabled      bool   `json:"payment_processor_enabled"`
	StripeProfessionalPriceID    string `json:"stripe_professional_price_id"`
	StripeEnterprisePriceID      string `json:"stripe_enterprise_price_id"`
	StripeInvestorPriceID        string `json:"stripe_investor_price_id"`
	PaymentSuccessURL            string `json:"payment_success_url"`
	PaymentCancelURL             string `json:"payment_cancel_url"`
	PaymentOnboardingCallbackURL string `json:"payment_onboarding_callback_url"`
	StripeThinWebhookSecret      string `json:"stripe_thin_webhook_secret"`

	WASMPublisherPrivateKeyHex string `json:"wasm_publisher_private_key_hex"`
}

// BootSecrets is the decrypted contents of boot.key with named fields.
type BootSecrets struct {
	Path string `json:"path"`

	MasterWalletKeyHex string `json:"master_wallet_key_hex"`
	RegistrationID     string `json:"registration_id"`

	JWTSecret      string `json:"jwt_secret"`
	GeminiAPIKey   string `json:"gemini_api_key"`
	DeepseekAPIKey string `json:"deepseek_api_key"`
	CerebrasAPIKey string `json:"cerebras_api_key"`

	Cloudflare Cloudflare `json:"cloudflare"`

	DeviceIP       string `json:"device_ip"`
	DevicePassword string `json:"device_password"`
	DeviceUsername string `json:"device_username"`

	StripeSecretKey    string `json:"stripe_secret_key"`
	DefaultGitHubToken string `json:"default_github_token"`
	SMTPPassword       string `json:"smtp_password"`
}

// Provider is the single secrets surface used by every service. Implementations
// must be safe for concurrent use.
type Provider interface {
	// Root returns nil, nil when this node has no root.key.
	Root(ctx context.Context) (*RootSecrets, error)
	// Boot returns nil, nil when this node has no boot.key.
	Boot(ctx context.Context) (*BootSecrets, error)
	// Signer returns a signing identity by name. Known names are "root",
	// "boot", and "validation" (root's key on Root nodes, boot's on Bootnodes).
	Signer(ctx context.Context, name string) (knirvsigning.RemoteSigner, error)
	Health(ctx context.Context) Status
}
