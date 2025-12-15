package colorconv

import (
	"image"
	"math/rand"
	"testing"
)

func TestRGBAToNV12FastMatchesReference(t *testing.T) {
	t.Parallel()

	const width, height = 128, 72
	img := image.NewRGBA(image.Rect(0, 0, width, height))
	rng := rand.New(rand.NewSource(1))
	rng.Read(img.Pix)

	dstA := make([]byte, width*height*3/2)
	dstB := make([]byte, width*height*3/2)

	if err := RGBAToNV12(img, dstA, width, height); err != nil {
		t.Fatalf("RGBAToNV12: %v", err)
	}
	if err := RGBAToNV12Fast(img, dstB, width, height); err != nil {
		t.Fatalf("RGBAToNV12Fast: %v", err)
	}
	if len(dstA) != len(dstB) {
		t.Fatalf("dst length mismatch: %d vs %d", len(dstA), len(dstB))
	}
	for i := range dstA {
		if dstA[i] != dstB[i] {
			t.Fatalf("mismatch at %d: %d != %d", i, dstA[i], dstB[i])
		}
	}
}

func TestRGBAToNV12RejectsOddDimensions(t *testing.T) {
	t.Parallel()

	img := image.NewRGBA(image.Rect(0, 0, 3, 3))
	dst := make([]byte, 100)
	if err := RGBAToNV12(img, dst, 3, 3); err == nil {
		t.Fatalf("expected error for odd dimensions")
	}
	if err := RGBAToNV12Fast(img, dst, 3, 3); err == nil {
		t.Fatalf("expected error for odd dimensions (fast)")
	}
}

