package knirv

import (
	"context"
	"testing"
)

func TestExecuteCryptoSHA256(t *testing.T) {
	data, err := NewClient().Execute(context.Background(), "crypto.sha256", []byte(`{"data":"knirv"}`))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"digest":"844ab93035e622284f4d0db575d2a4a29a89c06acc652925e7f0b2b0392d35cf"}`
	if string(data) != want {
		t.Fatalf("response = %s, want %s", data, want)
	}
}
