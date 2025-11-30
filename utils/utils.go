package utils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	jsoniter "github.com/json-iterator/go"
	"reflect"
	"unsafe"
)

var (
	JSON = jsoniter.Config{EscapeHTML: false, SortMapKeys: true, ValidateJsonRawMessage: true}.Froze()

	ErrEntityInvalid      = errors.New(`common.ENTITY_INVALID`)
	ErrFailedVerification = errors.New(`common.ENTITY_CHECK_FAILED`)
)

func If[T any](b bool, t, f T) T {
	if b {
		return t
	}
	return f
}

func Min[T int | int32 | int64 | uint | uint32 | uint64 | float32 | float64](a, b T) T {
	if a < b {
		return a
	}
	return b
}

func Max[T int | int32 | int64 | uint | uint32 | uint64 | float32 | float64](a, b T) T {
	if a > b {
		return a
	}
	return b
}

// XOR performs simple XOR encryption (deprecated, use StreamEncrypt instead)
// Kept for backwards compatibility during transition
func XOR(data []byte, key []byte) []byte {
	if len(key) == 0 {
		return data
	}
	for i := 0; i < len(data); i++ {
		data[i] = data[i] ^ key[i%len(key)]
	}
	return data
}

// StreamEncrypt encrypts data using AES-CTR for streaming purposes
// Uses the first 32 bytes of key as AES key and derives IV from key
// This is suitable for real-time streaming where each session has a unique key
func StreamEncrypt(data []byte, key []byte) []byte {
	if len(key) < 32 {
		// Fallback to XOR if key is too short (shouldn't happen)
		return XOR(data, key)
	}

	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return XOR(data, key)
	}

	// Derive IV from key (last 16 bytes or XOR of key bytes)
	iv := make([]byte, 16)
	if len(key) >= 48 {
		copy(iv, key[32:48])
	} else {
		// Derive IV by XORing key bytes (matches JavaScript implementation)
		for i := 0; i < len(key); i++ {
			iv[i%16] ^= key[i]
		}
	}

	result := make([]byte, len(data))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(result, data)
	return result
}

// StreamDecrypt decrypts data encrypted with StreamEncrypt
// AES-CTR is symmetric so encrypt and decrypt are the same operation
func StreamDecrypt(data []byte, key []byte) []byte {
	return StreamEncrypt(data, key)
}

func GenRandByte(n int) []byte {
	secBuffer := make([]byte, n)
	rand.Reader.Read(secBuffer)
	return secBuffer
}

func GetStrUUID() string {
	return hex.EncodeToString(GenRandByte(16))
}

func GetUUID() []byte {
	return GenRandByte(16)
}

func GetMD5(data []byte) ([]byte, string) {
	hash := md5.New()
	hash.Write(data)
	result := hash.Sum(nil)
	hash.Reset()
	return result, hex.EncodeToString(result)
}

// GetSHA256 returns SHA-256 hash, truncated to 16 bytes for AES IV compatibility
func GetSHA256(data []byte) ([]byte, string) {
	hash := sha256.New()
	hash.Write(data)
	result := hash.Sum(nil)
	return result[:16], hex.EncodeToString(result)
}

// Encrypt uses AES-CTR with random IV and SHA-256 for integrity
// Format: [Version(1)] [IV(16)] [SHA256-Checksum(16)] [Encrypted(data + nonce(64))]
// Version 2 uses SHA-256, Version 1 (legacy) uses MD5
func Encrypt(data []byte, key []byte) ([]byte, error) {
	// Generate random IV (more secure than deriving from plaintext)
	iv := make([]byte, 16)
	rand.Reader.Read(iv)

	// Add random nonce to prevent replay attacks
	nonce := make([]byte, 64)
	rand.Reader.Read(nonce)
	plaintext := append(data, nonce...)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Encrypt with random IV
	stream := cipher.NewCTR(block, iv)
	encBuffer := make([]byte, len(plaintext))
	stream.XORKeyStream(encBuffer, plaintext)

	// Calculate SHA-256 checksum (truncated to 16 bytes)
	checksum, _ := GetSHA256(plaintext)

	// Format: [Version(1)] [IV(16)] [Checksum(16)] [Encrypted]
	result := make([]byte, 1+16+16+len(encBuffer))
	result[0] = 2 // Version 2 = SHA-256
	copy(result[1:17], iv)
	copy(result[17:33], checksum)
	copy(result[33:], encBuffer)

	return result, nil
}

// Decrypt supports both V2 (SHA-256) and V1 (MD5/legacy) formats
func Decrypt(data []byte, key []byte) ([]byte, error) {
	dataLen := len(data)

	// Check for V2 format (starts with version byte 2)
	if dataLen > 33+64 && data[0] == 2 {
		return decryptV2(data, key)
	}

	// Legacy V1 format: MD5[16 bytes] + Data[n bytes] + Nonce[64 bytes]
	return decryptV1(data, key)
}

// decryptV2 handles new SHA-256 based encryption
func decryptV2(data []byte, key []byte) ([]byte, error) {
	// Format: [Version(1)] [IV(16)] [Checksum(16)] [Encrypted]
	dataLen := len(data)
	if dataLen <= 33+64 {
		return nil, ErrEntityInvalid
	}

	iv := data[1:17]
	expectedChecksum := data[17:33]
	encrypted := data[33:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	stream := cipher.NewCTR(block, iv)
	decBuffer := make([]byte, len(encrypted))
	stream.XORKeyStream(decBuffer, encrypted)

	// Verify checksum
	actualChecksum, _ := GetSHA256(decBuffer)
	if !bytes.Equal(actualChecksum, expectedChecksum) {
		return nil, ErrFailedVerification
	}

	// Remove nonce (last 64 bytes)
	return decBuffer[:len(decBuffer)-64], nil
}

// decryptV1 handles legacy MD5-based encryption for backwards compatibility
func decryptV1(data []byte, key []byte) ([]byte, error) {
	// MD5[16 bytes] + Data[n bytes] + Nonce[64 bytes]
	dataLen := len(data)
	if dataLen <= 16+64 {
		return nil, ErrEntityInvalid
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	stream := cipher.NewCTR(block, data[:16])
	decBuffer := make([]byte, dataLen-16)
	stream.XORKeyStream(decBuffer, data[16:])

	hash, _ := GetMD5(decBuffer)
	if !bytes.Equal(hash, data[:16]) {
		data = nil
		decBuffer = nil
		return nil, ErrFailedVerification
	}
	data = nil
	decBuffer = decBuffer[:dataLen-16-64]

	return decBuffer, nil
}

func FormatSize(size int64) string {
	sizes := []string{`B`, `KB`, `MB`, `GB`, `TB`, `PB`, `EB`, `ZB`, `YB`}
	i := 0
	for size >= 1024 && i < len(sizes)-1 {
		size /= 1024
		i++
	}
	return fmt.Sprintf(`%d%s`, size, sizes[i])
}

func BytesToString(b []byte, r ...int) string {
	sh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	bytesPtr := sh.Data
	bytesLen := sh.Len
	switch len(r) {
	case 1:
		r[0] = If(r[0] > bytesLen, bytesLen, r[0])
		bytesLen -= r[0]
		bytesPtr += uintptr(r[0])
	case 2:
		r[0] = If(r[0] > bytesLen, bytesLen, r[0])
		bytesLen = If(r[1] > bytesLen, bytesLen, r[1]) - r[0]
		bytesPtr += uintptr(r[0])
	}
	return *(*string)(unsafe.Pointer(&reflect.StringHeader{
		Data: bytesPtr,
		Len:  bytesLen,
	}))
}

func StringToBytes(s string, r ...int) []byte {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	strPtr := sh.Data
	strLen := sh.Len
	switch len(r) {
	case 1:
		r[0] = If(r[0] > strLen, strLen, r[0])
		strLen -= r[0]
		strPtr += uintptr(r[0])
	case 2:
		r[0] = If(r[0] > strLen, strLen, r[0])
		strLen = If(r[1] > strLen, strLen, r[1]) - r[0]
		strPtr += uintptr(r[0])
	}
	return *(*[]byte)(unsafe.Pointer(&reflect.SliceHeader{
		Data: strPtr,
		Len:  strLen,
		Cap:  strLen,
	}))
}

func GetSlicePrefix[T any](data *[]T, n int) *[]T {
	sliceHeader := (*reflect.SliceHeader)(unsafe.Pointer(data))
	return (*[]T)(unsafe.Pointer(&reflect.SliceHeader{
		Data: sliceHeader.Data,
		Len:  n,
		Cap:  n,
	}))
}

func GetSliceSuffix[T any](data *[]T, n int) *[]T {
	sliceHeader := (*reflect.SliceHeader)(unsafe.Pointer(data))
	return (*[]T)(unsafe.Pointer(&reflect.SliceHeader{
		Data: sliceHeader.Data + uintptr(sliceHeader.Len-n),
		Len:  n,
		Cap:  n,
	}))
}

func GetSliceChunk[T any](data *[]T, start, end int) *[]T {
	sliceHeader := (*reflect.SliceHeader)(unsafe.Pointer(data))
	return (*[]T)(unsafe.Pointer(&reflect.SliceHeader{
		Data: sliceHeader.Data + uintptr(start),
		Len:  end - start,
		Cap:  end - start,
	}))
}

func CheckBinaryPack(data []byte) (byte, byte, bool) {
	if len(data) >= 8 {
		if bytes.Equal(data[:4], []byte{34, 22, 19, 17}) {
			if data[4] == 20 || data[4] == 21 {
				return data[4], data[5], true
			}
		}
	}
	return 0, 0, false
}
