// Package noderole decides what a KNIRV node is (root, bootnode or client)
// and every capability that follows from it: the KNIRVCHAIN role, whether the
// Oracle runs and in which mode, whether the node is a validator, and which
// signing identity the node acts as.
//
// Resolve is pure: it takes key-file paths and unlock results as input and
// touches no filesystem, environment or clock. Callers gather the inputs once
// and render the result into the child environment (env.go). No other package
// may decide a node's role from a key file.
//
// The rules come from the node-role decisions (D-R1..D-R4):
//
//	root.key found   kind=root      chain=Root      oracle=active   validator=false
//	boot.key only    kind=bootnode  chain=Bootnode  oracle=standby  validator=true
//	neither          kind=client    chain=Client    oracle=off      validator=false
//
// root.key wins when both exist. A privileged role is never inherited without
// its key file, and an existing-but-locked key file keeps its kind while
// marking the node Degraded. Overrides may only lower privilege.
package noderole

// Kind is the node kind derived from which key file is present.
type Kind string

const (
	KindRoot     Kind = "root"
	KindBootnode Kind = "bootnode"
	KindClient   Kind = "client"
)

// OracleMode is how the local KNIRVORACLE runs.
type OracleMode string

const (
	// OracleActive serves every route and may sign and mutate state.
	OracleActive OracleMode = "active"
	// OracleStandby is a read-only failover ledger: read and replication
	// routes only.
	OracleStandby OracleMode = "standby"
	// OracleOff means no Oracle process runs on this node.
	OracleOff OracleMode = "off"
)

// KNIRVCHAIN role values. They are the strings KNIRVCHAIN's -role flag
// accepts; "validator" is a KNIRVORACLE property, not a chain role.
const (
	ChainRoot     = "Root"
	ChainBootnode = "Bootnode"
	ChainPeer     = "Peer"
	ChainClient   = "Client"
)

// Signer names understood by secrets.Provider.Signer.
const (
	SignerRoot     = "root-owner"
	SignerBootnode = "bootnode-master"
)

// Override is configuration that may lower, never raise, a derived
// capability. Empty strings and a nil Validator mean "no override".
// ChainRole comes from config chain.role; OracleMode and Validator from the
// node's validator settings (config today, OpenBao once Task 2a.6 lands).
type Override struct {
	ChainRole  string
	OracleMode OracleMode
	Validator  *bool
}

// Inputs is everything Resolve needs. Paths are discovery results and may be
// empty; Unlocked says whether the corresponding file could be decrypted.
type Inputs struct {
	RootKeyPath  string
	BootKeyPath  string
	RootUnlocked bool
	BootUnlocked bool
	Override     Override
}

// Resolution is the single source of truth for a node's capabilities.
type Resolution struct {
	Kind       Kind
	KeyPath    string
	ChainRole  string
	Oracle     OracleMode
	Validator  bool
	SignerName string
	Degraded   bool
	Reason     string
	// Ignored lists overrides that were rejected because they tried to raise
	// privilege, or that named an unknown value. Each entry is a complete
	// sentence suitable for a WARN log.
	Ignored []string
}

// Signer returns the secrets.Provider signer name for the node, or "" for a
// client (which holds no identity).
func (r Resolution) Signer() string { return r.SignerName }

// IsRoot reports whether this node is a root server.
func (r Resolution) IsRoot() bool { return r.Kind == KindRoot }

// IsBootnode reports whether this node is a boot node.
func (r Resolution) IsBootnode() bool { return r.Kind == KindBootnode }
