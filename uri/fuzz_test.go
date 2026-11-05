package uri

import "testing"

// Exercise untrusted URI bytes through the same WASI binding used by services.
func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"knirv://node.chain/",
		"knirv://network/skill_1234",
		"knirv://dve/id/name",
		"knirv://auth?token=test",
		"knirv://a.b.c/%ff?x=%00",
		"\x00\xff",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		result := Parse(raw)
		if result.Kind == KindCanonical {
			roundTrip := Parse(result.Canonical)
			if roundTrip.Kind != KindCanonical || roundTrip.Canonical != result.Canonical {
				t.Fatalf("canonical URI did not round trip: %q", result.Canonical)
			}
		}
	})
}
