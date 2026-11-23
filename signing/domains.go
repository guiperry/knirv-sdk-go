package signing

// Reserved signing domains, purposes and roles shared by Go, Rust and
// TypeScript. KnirvNetwork controller §3.4 is the canonical table; keep these
// values in sync with core/src/signing.rs and npm-package/src/signing.ts.
const (
	// ScenesDomain signs 3D scene manifests authored by a scene signer.
	ScenesDomain = "knirv.scenes"
	// PurposeSceneManifest is the sole purpose under ScenesDomain.
	PurposeSceneManifest = "scene-manifest"
	// RoleSceneSigner is the registered service role that may sign scenes.
	RoleSceneSigner = "scene-signer"
)

// U12 reserved chain and oracle domains. Mirrors core/src/signing.rs
// (CHAIN_DOMAIN, ORACLE_DOMAIN and their purposes).
const (
	// ChainDomain signs KNIRVCHAIN checkpoints, service messages and block proposals.
	ChainDomain = "knirv.chain"
	// PurposeChainCheckpoint is the checkpoint purpose under ChainDomain.
	PurposeChainCheckpoint = "chain-checkpoint"
	// PurposeServiceMessage is the service-to-service purpose under ChainDomain.
	PurposeServiceMessage = "service-message"
	// PurposeBlockProposer is the block-proposer purpose under ChainDomain.
	PurposeBlockProposer = "block-proposer"
	// PurposeChainRegistration is the bond-enrollment purpose under ChainDomain.
	PurposeChainRegistration = "chain-registration"
	// OracleDomain authorises NRN mints signed by the oracle.
	OracleDomain = "knirv.oracle"
	// PurposeOracleMint is the mint-authorisation purpose under OracleDomain.
	PurposeOracleMint = "oracle-mint"
	// PurposeOracleTransfer, PurposeOracleBurn, PurposeWalletRegistration and
	// PurposeVerifierAttestation are the live purposes under OracleDomain.
	PurposeOracleTransfer      = "oracle-transfer"
	PurposeOracleBurn          = "oracle-burn"
	PurposeWalletRegistration  = "wallet-registration"
	PurposeVerifierAttestation = "verifier-attestation"
)
