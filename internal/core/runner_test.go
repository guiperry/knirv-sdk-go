package core

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

func request(op, payload string) []byte {
	return []byte(`{"version":1,"operation":"` + op + `","payload":` + payload + `}`)
}

type envelope struct {
	Payload json.RawMessage `json:"payload"`
	Error   *struct {
		Message string `json:"message"`
	} `json:"error"`
}

func invoke(t *testing.T, r *Runner, op, payload string) envelope {
	t.Helper()
	raw, err := r.Invoke(context.Background(), request(op, payload))
	if err != nil {
		t.Fatalf("%s: %v", op, err)
	}
	var out envelope
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("%s: bad response %q: %v", op, raw, err)
	}
	return out
}

func TestSha256KnownAnswer(t *testing.T) {
	r, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(context.Background())
	out := invoke(t, r, "crypto.sha256", `{"data":"knirv"}`)
	if out.Error != nil || string(out.Payload) != `{"digest":"844ab93035e622284f4d0db575d2a4a29a89c06acc652925e7f0b2b0392d35cf"}` {
		t.Fatalf("response = %+v / %s", out.Error, out.Payload)
	}
}

func TestConcurrentCallsGetTheirOwnAnswers(t *testing.T) {
	r, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(context.Background())
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// The id is derived from i, so a mixed-up buffer shows as a wrong answer.
			out := invoke(t, r, "uri.derive_id", `{"raw":"id-`+string(rune('a'+i%26))+`"}`)
			again := invoke(t, r, "uri.derive_id", `{"raw":"id-`+string(rune('a'+i%26))+`"}`)
			if out.Error != nil || string(out.Payload) != string(again.Payload) {
				t.Errorf("call %d: %s vs %s", i, out.Payload, again.Payload)
			}
		}(i)
	}
	wg.Wait()
	if r.live > r.max {
		t.Fatalf("pool grew past its cap: live=%d max=%d", r.live, r.max)
	}
}

// A call that fails inside an instance must not poison the pool: the instance
// is discarded and the next call gets a fresh one.
func TestFailedInstanceIsDiscardedAndReplaced(t *testing.T) {
	r, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(context.Background())
	invoke(t, r, "crypto.sha256", `{"data":"warm"}`) // one pooled instance

	inst := <-r.pool
	_ = inst.module.Close(context.Background()) // simulate a dead instance
	r.pool <- inst

	if _, err := r.Invoke(context.Background(), request("crypto.sha256", `{"data":"x"}`)); !errors.Is(err, ErrTrapped) {
		t.Fatalf("error = %v, want ErrTrapped", err)
	}
	if r.live != 0 {
		t.Fatalf("dead instance was not discarded: live=%d", r.live)
	}
	if out := invoke(t, r, "crypto.sha256", `{"data":"x"}`); out.Error != nil {
		t.Fatalf("pool did not recover: %+v", out.Error)
	}
}

func TestHostileInputNeverTrapsOrCorruptsTheInstance(t *testing.T) {
	r, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(context.Background())
	hostile := []string{
		"AQID",         // 3 junk bytes
		"Cv////////8B", // length-delimited, length 2^64-1
		"Cv////8P",     // length 2^32-1
		"CQECAw==",     // truncated fixed64
		"",             // empty
	}
	for _, op := range []string{"signing.parse_message_envelope", "relay.parse", "wasm.assignment.parse", "signing.parse_action_body"} {
		for _, b64 := range hostile {
			raw, err := r.Invoke(context.Background(), request(op, `{"bytes_base64":"`+b64+`","body_base64":"`+b64+`"}`))
			if err != nil {
				t.Fatalf("%s %q trapped: %v", op, b64, err)
			}
			if !json.Valid(raw) {
				t.Fatalf("%s %q: invalid response %q", op, b64, raw)
			}
		}
	}
	if out := invoke(t, r, "crypto.sha256", `{"data":"still alive"}`); out.Error != nil {
		t.Fatal("instance unusable after hostile input")
	}
}

// The module reads the host clock: newCLISupervisorRelay without an explicit
// issue time must use real time, not wazero's fixed fake clock.
func TestModuleSeesTheRealClock(t *testing.T) {
	r, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(context.Background())
	out := invoke(t, r, "relay.new_cli_supervisor", `{"request_id":"r","user_subject":"u","device_id":"d","target_id":"t","capability":"c","sequence":1,"lease_epoch":0,"payload":[1],"ttl_seconds":60}`)
	if out.Error != nil {
		t.Fatalf("error: %s", out.Error.Message)
	}
	var relay struct {
		IssuedAt int64 `json:"issued_at_unix"`
	}
	if err := json.Unmarshal(out.Payload, &relay); err != nil {
		t.Fatal(err)
	}
	if drift := time.Now().Unix() - relay.IssuedAt; drift < -5 || drift > 5 {
		t.Fatalf("module clock is off by %ds (fake clock?)", drift)
	}
}

func TestCancelledContextIsRejectedBeforeRunning(t *testing.T) {
	r, err := New(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Invoke(ctx, request("crypto.sha256", `{"data":"x"}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
}
