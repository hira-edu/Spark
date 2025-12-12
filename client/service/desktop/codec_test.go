//go:build !headless
// +build !headless

package desktop

import "testing"

func TestProxyCodecFallbackForAvif(t *testing.T) {
	t.Parallel()

	codec := NewAVIFCodec(75)
	proxy, ok := codec.(*ProxyCodec)
	if !ok {
		t.Fatalf("expected ProxyCodec, got %T", codec)
	}

	if codec.Name() != CodecNameJPEG {
		t.Fatalf("expected actual codec name %q, got %q", CodecNameJPEG, codec.Name())
	}
	if codec.Type() != CodecTypeJPEG {
		t.Fatalf("expected actual codec type %d, got %d", CodecTypeJPEG, codec.Type())
	}
	if proxy.RequestedName() != CodecNameAVIF {
		t.Fatalf("expected requested codec %q, got %q", CodecNameAVIF, proxy.RequestedName())
	}
	if proxy.RequestedType() != CodecTypeAVIF {
		t.Fatalf("expected requested codec type %d, got %d", CodecTypeAVIF, proxy.RequestedType())
	}
	if !proxy.HasFallback() {
		t.Fatalf("expected HasFallback to be true")
	}
}

func TestHardwareProxyCodecFallback(t *testing.T) {
	t.Parallel()

	codec := NewHardwareCodec(CodecTypeH264, 60, &HardwareCodecSupport{H264Available: true})
	proxy, ok := codec.(*ProxyCodec)
	if !ok {
		t.Fatalf("expected ProxyCodec, got %T", codec)
	}

	if codec.Name() != CodecNameJPEG {
		t.Fatalf("expected Name to report actual codec %q, got %q", CodecNameJPEG, codec.Name())
	}
	if codec.Type() != CodecTypeJPEG {
		t.Fatalf("expected Type to report %d, got %d", CodecTypeJPEG, codec.Type())
	}
	if proxy.RequestedName() != CodecNameH264 {
		t.Fatalf("expected RequestedName %q, got %q", CodecNameH264, proxy.RequestedName())
	}
	if proxy.RequestedType() != CodecTypeH264 {
		t.Fatalf("expected RequestedType %d, got %d", CodecTypeH264, proxy.RequestedType())
	}
	if !proxy.HasFallback() {
		t.Fatalf("expected HasFallback true for hardware codec without encoder")
	}
}
