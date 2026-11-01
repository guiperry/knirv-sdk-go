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
