package libtrust

import (
	"testing"
)

type generateFunc func() (PrivateKey, error)

func runGenerateBench(b *testing.B, f generateFunc, name string) {
	for i := 0; i < b.N; i++ {
		_, err := f()
		if err != nil {
			b.Fatalf("Error generating %s: %s", name, err)
		}
	}
}

func BenchmarkECP256Generate(b *testing.B) {
	runGenerateBench(b, GenerateECP256PrivateKey, "P256")
}
