//go:build ignore

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
)

const (
	TrailerMagic      = "SPARKCFG"
	TrailerFooterSize = 20
	ConfigBufferSize  = 2048
)

type trailerFooter struct {
	Magic    [8]byte
	Version  uint16
	Reserved uint16
	Length   uint32
	CRC32    uint32
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run test_config.go <client_binary>")
		os.Exit(1)
	}
	path := os.Args[1]

	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer file.Close()

	stat, _ := file.Stat()
	fmt.Printf("File size: %d bytes\n", stat.Size())

	// Read footer
	footerOffset := stat.Size() - TrailerFooterSize
	buf := make([]byte, TrailerFooterSize)
	file.ReadAt(buf, footerOffset)

	var footer trailerFooter
	binary.Read(bytes.NewReader(buf), binary.LittleEndian, &footer)

	fmt.Printf("Magic: %s\n", string(footer.Magic[:]))
	fmt.Printf("Version: %d\n", footer.Version)
	fmt.Printf("Length: %d\n", footer.Length)
	fmt.Printf("CRC32: %08x\n", footer.CRC32)

	if string(footer.Magic[:]) != TrailerMagic {
		fmt.Println("ERROR: Magic mismatch!")
		os.Exit(1)
	}

	// Read config buffer
	length := int64(footer.Length)
	data := make([]byte, length)
	file.ReadAt(data, footerOffset-length)

	// Verify CRC
	computed := crc32.ChecksumIEEE(data)
	fmt.Printf("Computed CRC32: %08x\n", computed)
	if computed != footer.CRC32 {
		fmt.Println("ERROR: CRC mismatch!")
		os.Exit(1)
	}
	fmt.Println("CRC verification: PASSED")

	// Parse data length (big-endian 2-byte)
	dataLen := int(binary.BigEndian.Uint16(data[:2]))
	fmt.Printf("Data length: %d\n", dataLen)

	if dataLen <= 0 || dataLen > len(data)-2 {
		fmt.Printf("ERROR: Invalid data length (max: %d)\n", len(data)-2)
		os.Exit(1)
	}

	cfgBytes := data[2 : 2+dataLen]
	fmt.Printf("Config bytes length: %d\n", len(cfgBytes))

	// Decrypt config
	// cfgBytes = configKey[16] + encryptedData
	if len(cfgBytes) <= 16 {
		fmt.Println("ERROR: Config bytes too short")
		os.Exit(1)
	}

	configKey := cfgBytes[:16]
	encData := cfgBytes[16:]
	fmt.Printf("Config key: %s\n", hex.EncodeToString(configKey))
	fmt.Printf("Encrypted data length: %d\n", len(encData))

	// Use 16-byte key (AES-128) - matches client.go's decrypt()
	// encData format: MD5[16] + encrypted
	if len(encData) <= 16 {
		fmt.Println("ERROR: Encrypted data too short")
		os.Exit(1)
	}

	md5Hash := encData[:16]
	encrypted := encData[16:]
	fmt.Printf("MD5 hash: %s\n", hex.EncodeToString(md5Hash))

	// Decrypt using AES-128-CTR with MD5 as IV (same as client.go)
	block, _ := aes.NewCipher(configKey) // 16-byte key
	stream := cipher.NewCTR(block, md5Hash)
	decrypted := make([]byte, len(encrypted))
	stream.XORKeyStream(decrypted, encrypted)

	// Verify MD5
	hash := md5.Sum(decrypted)
	fmt.Printf("Computed MD5: %s\n", hex.EncodeToString(hash[:]))

	if bytes.Equal(hash[:], md5Hash) {
		fmt.Println("MD5 verification: PASSED")
		fmt.Printf("\nDecrypted config:\n%s\n", string(decrypted))

		// Pretty print
		var cfg map[string]interface{}
		if err := json.Unmarshal(decrypted, &cfg); err != nil {
			fmt.Printf("JSON parse error: %v\n", err)
		} else {
			pretty, _ := json.MarshalIndent(cfg, "", "  ")
			fmt.Printf("\nParsed config:\n%s\n", string(pretty))
		}
	} else {
		fmt.Println("MD5 verification: FAILED")
		fmt.Printf("Decrypted (may be garbage): %s\n", hex.EncodeToString(decrypted[:min(32, len(decrypted))]))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
