package knirv

// NativeError is a structured failure returned by the Rust core through the
// binding envelope. Its message never exposes memory addresses or Rust types.
type NativeError struct{ Message string }

func (e *NativeError) Error() string {
	if e.Message == "" {
		return "KNIRV native core operation failed"
	}
	return "KNIRV native core: " + e.Message
}
