//go:build ignore

// gen_config.go - Client Configuration Generator
//
// This tool generates properly authenticated client configurations that work
// with the Spark server's salt-based authentication system.

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash/crc32"
	"io"
	"math/big"
	"os"
)

const (
	TrailerMagic      = "SPARKCFG"
	trailerVersion    = uint16(1)
	TrailerFooterSize = 20
	ConfigBufferSize  = 384

	DefaultHost   = "localhost"
	DefaultPort   = 8443
	DefaultSecure = false
	DefaultPath   = "/"
	DefaultSalt   = "testsalt1234567890123"
)

type trailerFooter struct {
	Magic    [8]byte
	Version  uint16
	Reserved uint16
	Length   uint32
	CRC32    uint32
}

type clientCfg struct {
	Secure         bool   `json:"secure"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Path           string `json:"path"`
	UUID           string `json:"uuid"`
	Key            string `json:"key"`
	EnableQUIC     bool   `json:"enable_quic"`
	QUICPort       int    `json:"quic_port"`
	EnableLongPoll bool   `json:"enable_longpoll"`
	EnableDNS      bool   `json:"enable_dns"`
	DNSDomain      string `json:"dns_domain"`
	DNSServer      string `json:"dns_server"`
	EnableMimicry  bool   `json:"enable_mimicry"`
}

func getUUID() []byte {
	uuid := make([]byte, 16)
	if _, err := rand.Read(uuid); err != nil {
		panic(fmt.Sprintf("failed to generate UUID: %v", err))
	}
	return uuid
}

// deriveSaltBytes converts salt string to 24-byte key (matches server config/config.go)
func deriveSaltBytes(salt string) []byte {
	if len(salt) > 24 {
		panic("salt must be 24 characters or less")
	}
	saltBytes := []byte(salt)
	saltBytes = append(saltBytes, bytes.Repeat([]byte{25}, 24)...)
	return saltBytes[:24]
}

// encAES - Encryption removed; TLS provides transport security.
// Returns data unchanged. The key and keyLen parameters are kept for API compatibility.
func encAES(data []byte, key []byte, keyLen int) ([]byte, error) {
	_, _ = key, keyLen // Unused - kept for API compatibility
	// Return a copy for safety (no encryption needed - TLS handles security)
	return append([]byte(nil), data...), nil
}

// generateClientKey creates auth key from UUID.
// Encryption removed - key is now just the UUID itself (TLS provides security).
// Server will compare Key == UUID for authentication.
func generateClientKey(uuid []byte, saltBytes []byte) ([]byte, error) {
	_ = saltBytes // Unused - kept for API compatibility
	// Return a copy of UUID as the key (no encryption needed)
	return append([]byte(nil), uuid...), nil
}

func genConfig(cfg clientCfg) ([]byte, error) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}

	// Use 16-byte key for config encryption (AES-128)
	// This matches client.go's decrypt() which uses the raw 16-byte configKey
	configKey := getUUID() // 16 bytes
	data, err = encAES(data, configKey, 16)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt config: %w", err)
	}
	final := append(configKey, data...)

	dataLen := big.NewInt(int64(len(final))).Bytes()
	dataLen = append(bytes.Repeat([]byte{0}, 2-len(dataLen)), dataLen...)
	final = append(dataLen, final...)

	for len(final) < ConfigBufferSize {
		final = append(final, getUUID()...)
	}
	return final[:ConfigBufferSize], nil
}

func buildTrailerFooter(data []byte) []byte {
	footer := trailerFooter{
		Version:  trailerVersion,
		Reserved: 0,
		Length:   uint32(len(data)),
		CRC32:    crc32.ChecksumIEEE(data),
	}
	copy(footer.Magic[:], []byte(TrailerMagic))

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, footer)
	return buf.Bytes()
}

func main() {
	host := flag.String("host", DefaultHost, "Server hostname")
	port := flag.Int("port", DefaultPort, "Server port")
	secure := flag.Bool("secure", DefaultSecure, "Use TLS")
	salt := flag.String("salt", DefaultSalt, "Server salt for authentication")
	path := flag.String("path", DefaultPath, "WebSocket path")
	enableLongPoll := flag.Bool("longpoll", true, "Enable long polling transport")
	enableQUIC := flag.Bool("quic", false, "Enable QUIC transport")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <input_binary> <output_binary>\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Generates a configured Spark client binary with proper authentication.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() != 2 {
		flag.Usage()
		os.Exit(1)
	}

	inputPath := flag.Arg(0)
	outputPath := flag.Arg(1)

	if len(*salt) > 24 {
		fmt.Fprintf(os.Stderr, "Error: salt must be 24 characters or less\n")
		os.Exit(1)
	}

	saltBytes := deriveSaltBytes(*salt)

	uuidBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, uuidBytes); err != nil {
		fmt.Fprintf(os.Stderr, "Error generating UUID: %v\n", err)
		os.Exit(1)
	}

	keyBytes, err := generateClientKey(uuidBytes, saltBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating key: %v\n", err)
		os.Exit(1)
	}

	cfg := clientCfg{
		Secure:         *secure,
		Host:           *host,
		Port:           *port,
		Path:           *path,
		UUID:           hex.EncodeToString(uuidBytes),
		Key:            hex.EncodeToString(keyBytes),
		EnableQUIC:     *enableQUIC,
		QUICPort:       *port,
		EnableLongPoll: *enableLongPoll,
		EnableDNS:      false,
		DNSDomain:      "",
		DNSServer:      "8.8.8.8:53",
		EnableMimicry:  false,
	}

	cfgBytes, err := genConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error generating config: %v\n", err)
		os.Exit(1)
	}

	inputData, err := os.ReadFile(inputPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading input binary: %v\n", err)
		os.Exit(1)
	}

	trailerFooterBytes := buildTrailerFooter(cfgBytes)

	var output bytes.Buffer
	output.Write(inputData)
	output.Write(cfgBytes)
	output.Write(trailerFooterBytes)

	if err := os.WriteFile(outputPath, output.Bytes(), 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing output: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Configured client written to: %s\n", outputPath)
	fmt.Printf("\nConfiguration:\n")
	fmt.Printf("  UUID:      %s\n", cfg.UUID)
	fmt.Printf("  Host:      %s\n", cfg.Host)
	fmt.Printf("  Port:      %d\n", cfg.Port)
	fmt.Printf("  Path:      %s\n", cfg.Path)
	fmt.Printf("  Secure:    %v\n", cfg.Secure)
	fmt.Printf("  LongPoll:  %v\n", cfg.EnableLongPoll)
	fmt.Printf("  QUIC:      %v\n", cfg.EnableQUIC)
	fmt.Printf("\nKey Length:  %d bytes (encrypted UUID)\n", len(keyBytes))
}
