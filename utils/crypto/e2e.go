// Package crypto provides end-to-end encryption for Rocket remote desktop.
// Based on RustDesk's encryption approach with industry-standard algorithms.
//
// Security Design (2025 Best Practices):
// - Key Exchange: X25519 ECDH (Curve25519)
// - Symmetric Encryption: AES-256-GCM (AEAD)
// - Key Derivation: HKDF-SHA256
// - Nonce: 12-byte counter + random prefix (prevents reuse)
//
// Protocol Flow:
// 1. Both parties generate ephemeral X25519 key pairs
// 2. Exchange public keys over TLS
// 3. Derive shared secret via ECDH
// 4. Use HKDF to derive encryption key
// 5. Encrypt all frames with AES-256-GCM
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// E2E encryption constants
const (
	// KeySize is the size of encryption keys (256 bits)
	KeySize = 32

	// NonceSize is the size of AES-GCM nonce (96 bits)
	NonceSize = 12

	// TagSize is the size of AES-GCM authentication tag (128 bits)
	TagSize = 16

	// PublicKeySize is the size of X25519 public key
	PublicKeySize = 32

	// PrivateKeySize is the size of X25519 private key
	PrivateKeySize = 32

	// MaxNonceCounter before re-keying (2^32 messages per key)
	MaxNonceCounter = 1 << 32
)

var (
	// ErrKeyExchangeFailed indicates ECDH key exchange failure
	ErrKeyExchangeFailed = errors.New("e2e: key exchange failed")

	// ErrDecryptionFailed indicates decryption or authentication failure
	ErrDecryptionFailed = errors.New("e2e: decryption failed")

	// ErrNonceOverflow indicates nonce counter exceeded safe limit
	ErrNonceOverflow = errors.New("e2e: nonce counter overflow, re-key required")

	// ErrInvalidKeySize indicates incorrect key length
	ErrInvalidKeySize = errors.New("e2e: invalid key size")

	// ErrSessionNotEstablished indicates encryption session not initialized
	ErrSessionNotEstablished = errors.New("e2e: session not established")
)

// KeyPair holds X25519 public/private key pair for ECDH
type KeyPair struct {
	PublicKey  [PublicKeySize]byte
	PrivateKey [PrivateKeySize]byte
}

// GenerateKeyPair creates a new X25519 key pair for ECDH key exchange.
// Uses crypto/rand for secure random number generation.
func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}

	// Generate random private key
	if _, err := io.ReadFull(rand.Reader, kp.PrivateKey[:]); err != nil {
		return nil, err
	}

	// Clamp private key per X25519 spec (RFC 7748)
	kp.PrivateKey[0] &= 248
	kp.PrivateKey[31] &= 127
	kp.PrivateKey[31] |= 64

	// Derive public key
	curve25519.ScalarBaseMult(&kp.PublicKey, &kp.PrivateKey)

	return kp, nil
}

// Session represents an E2E encrypted session between two parties.
// Thread-safe for concurrent use.
type Session struct {
	// Encryption state
	encryptKey [KeySize]byte
	decryptKey [KeySize]byte
	encryptGCM cipher.AEAD
	decryptGCM cipher.AEAD

	// Nonce counters (atomic for thread-safety)
	encryptNonce atomic.Uint64
	decryptNonce atomic.Uint64

	// Random nonce prefix (4 bytes, unique per session)
	noncePrefix [4]byte

	// Session state
	established atomic.Bool
	mu          sync.RWMutex
}

// NewSession creates a new E2E encryption session.
// Call EstablishWithPeerKey to complete key exchange.
func NewSession() *Session {
	s := &Session{}
	// Generate random nonce prefix for this session
	rand.Read(s.noncePrefix[:])
	return s
}

// EstablishWithPeerKey completes ECDH key exchange and derives encryption keys.
// localKeyPair: our X25519 key pair
// peerPublicKey: remote party's public key
// isInitiator: true if we initiated the connection (affects key derivation order)
func (s *Session) EstablishWithPeerKey(localKeyPair *KeyPair, peerPublicKey []byte, isInitiator bool) error {
	if len(peerPublicKey) != PublicKeySize {
		return ErrInvalidKeySize
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Perform X25519 ECDH
	var peerPub [PublicKeySize]byte
	copy(peerPub[:], peerPublicKey)

	sharedSecret, err := curve25519.X25519(localKeyPair.PrivateKey[:], peerPub[:])
	if err != nil {
		return ErrKeyExchangeFailed
	}

	// Derive encryption keys using HKDF-SHA256
	// Different keys for each direction to prevent reflection attacks
	salt := make([]byte, 32)
	copy(salt[:16], localKeyPair.PublicKey[:16])
	copy(salt[16:], peerPub[:16])

	// Info string includes direction to derive different keys
	var encryptInfo, decryptInfo string
	if isInitiator {
		encryptInfo = "rocket-e2e-initiator-to-responder"
		decryptInfo = "rocket-e2e-responder-to-initiator"
	} else {
		encryptInfo = "rocket-e2e-responder-to-initiator"
		decryptInfo = "rocket-e2e-initiator-to-responder"
	}

	// Derive encryption key
	encKDF := hkdf.New(sha256.New, sharedSecret, salt, []byte(encryptInfo))
	if _, err := io.ReadFull(encKDF, s.encryptKey[:]); err != nil {
		return err
	}

	// Derive decryption key
	decKDF := hkdf.New(sha256.New, sharedSecret, salt, []byte(decryptInfo))
	if _, err := io.ReadFull(decKDF, s.decryptKey[:]); err != nil {
		return err
	}

	// Initialize AES-GCM ciphers
	encBlock, err := aes.NewCipher(s.encryptKey[:])
	if err != nil {
		return err
	}
	s.encryptGCM, err = cipher.NewGCM(encBlock)
	if err != nil {
		return err
	}

	decBlock, err := aes.NewCipher(s.decryptKey[:])
	if err != nil {
		return err
	}
	s.decryptGCM, err = cipher.NewGCM(decBlock)
	if err != nil {
		return err
	}

	// Mark session as established
	s.established.Store(true)

	return nil
}

// EstablishWithSharedSecret initializes encryption with a pre-shared secret.
// Useful for session tokens or password-derived keys.
func (s *Session) EstablishWithSharedSecret(secret []byte) error {
	if len(secret) < 16 {
		return ErrInvalidKeySize
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Derive encryption keys using HKDF-SHA256
	salt := []byte("rocket-e2e-shared-secret-salt")

	// Derive encryption key
	encKDF := hkdf.New(sha256.New, secret, salt, []byte("rocket-e2e-encrypt"))
	if _, err := io.ReadFull(encKDF, s.encryptKey[:]); err != nil {
		return err
	}

	// Derive decryption key (same as encrypt for shared secret mode)
	decKDF := hkdf.New(sha256.New, secret, salt, []byte("rocket-e2e-decrypt"))
	if _, err := io.ReadFull(decKDF, s.decryptKey[:]); err != nil {
		return err
	}

	// Initialize AES-GCM ciphers
	encBlock, err := aes.NewCipher(s.encryptKey[:])
	if err != nil {
		return err
	}
	s.encryptGCM, err = cipher.NewGCM(encBlock)
	if err != nil {
		return err
	}

	decBlock, err := aes.NewCipher(s.decryptKey[:])
	if err != nil {
		return err
	}
	s.decryptGCM, err = cipher.NewGCM(decBlock)
	if err != nil {
		return err
	}

	s.established.Store(true)
	return nil
}

// IsEstablished returns true if key exchange is complete
func (s *Session) IsEstablished() bool {
	return s.established.Load()
}

// Encrypt encrypts plaintext with AES-256-GCM.
// Returns: nonce (12 bytes) + ciphertext + tag (16 bytes)
// Thread-safe, uses atomic nonce counter.
func (s *Session) Encrypt(plaintext []byte) ([]byte, error) {
	if !s.established.Load() {
		return nil, ErrSessionNotEstablished
	}

	// Get and increment nonce counter atomically
	counter := s.encryptNonce.Add(1)
	if counter > MaxNonceCounter {
		return nil, ErrNonceOverflow
	}

	// Build nonce: prefix (4) + counter (8)
	nonce := make([]byte, NonceSize)
	copy(nonce[:4], s.noncePrefix[:])
	binary.BigEndian.PutUint64(nonce[4:], counter)

	// Encrypt with GCM (includes authentication tag)
	s.mu.RLock()
	ciphertext := s.encryptGCM.Seal(nil, nonce, plaintext, nil)
	s.mu.RUnlock()

	// Return nonce + ciphertext
	result := make([]byte, NonceSize+len(ciphertext))
	copy(result[:NonceSize], nonce)
	copy(result[NonceSize:], ciphertext)

	return result, nil
}

// Decrypt decrypts ciphertext with AES-256-GCM.
// Input format: nonce (12 bytes) + ciphertext + tag (16 bytes)
// Returns plaintext or error if authentication fails.
func (s *Session) Decrypt(data []byte) ([]byte, error) {
	if !s.established.Load() {
		return nil, ErrSessionNotEstablished
	}

	if len(data) < NonceSize+TagSize {
		return nil, ErrDecryptionFailed
	}

	nonce := data[:NonceSize]
	ciphertext := data[NonceSize:]

	s.mu.RLock()
	plaintext, err := s.decryptGCM.Open(nil, nonce, ciphertext, nil)
	s.mu.RUnlock()

	if err != nil {
		return nil, ErrDecryptionFailed
	}

	// Update decrypt nonce for replay detection (optional)
	counter := binary.BigEndian.Uint64(nonce[4:])
	s.decryptNonce.Store(counter)

	return plaintext, nil
}

// EncryptFrame encrypts a desktop frame with minimal allocation.
// Reuses the input buffer header for the nonce.
// Returns: magic (5) + nonce (12) + encrypted(op + event + payload) + tag (16)
func (s *Session) EncryptFrame(header []byte, payload []byte) ([]byte, error) {
	if !s.established.Load() {
		return nil, ErrSessionNotEstablished
	}

	// Combine header suffix + payload as plaintext
	// header[0:5] = magic (preserved)
	// header[5:22] = op + event (encrypted)
	plaintext := make([]byte, len(header)-5+len(payload))
	copy(plaintext, header[5:])
	copy(plaintext[len(header)-5:], payload)

	// Get nonce
	counter := s.encryptNonce.Add(1)
	if counter > MaxNonceCounter {
		return nil, ErrNonceOverflow
	}
	nonce := make([]byte, NonceSize)
	copy(nonce[:4], s.noncePrefix[:])
	binary.BigEndian.PutUint64(nonce[4:], counter)

	// Encrypt
	s.mu.RLock()
	ciphertext := s.encryptGCM.Seal(nil, nonce, plaintext, header[:5]) // AAD = magic bytes
	s.mu.RUnlock()

	// Build output: magic + nonce + ciphertext
	result := make([]byte, 5+NonceSize+len(ciphertext))
	copy(result[:5], header[:5])
	copy(result[5:5+NonceSize], nonce)
	copy(result[5+NonceSize:], ciphertext)

	return result, nil
}

// DecryptFrame decrypts a desktop frame.
// Input: magic (5) + nonce (12) + ciphertext + tag (16)
// Returns reconstructed header + payload
func (s *Session) DecryptFrame(data []byte) (header []byte, payload []byte, err error) {
	if !s.established.Load() {
		return nil, nil, ErrSessionNotEstablished
	}

	minLen := 5 + NonceSize + TagSize + 17 // magic + nonce + tag + min header
	if len(data) < minLen {
		return nil, nil, ErrDecryptionFailed
	}

	magic := data[:5]
	nonce := data[5 : 5+NonceSize]
	ciphertext := data[5+NonceSize:]

	s.mu.RLock()
	plaintext, err := s.decryptGCM.Open(nil, nonce, ciphertext, magic) // AAD = magic bytes
	s.mu.RUnlock()

	if err != nil {
		return nil, nil, ErrDecryptionFailed
	}

	// Reconstruct header (magic + decrypted op + event)
	if len(plaintext) < 17 {
		return nil, nil, ErrDecryptionFailed
	}
	header = make([]byte, 22) // magic(5) + op(1) + event(16)
	copy(header[:5], magic)
	copy(header[5:], plaintext[:17])

	payload = plaintext[17:]

	return header, payload, nil
}

// Zero wipes sensitive key material from memory
func (s *Session) Zero() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.encryptKey {
		s.encryptKey[i] = 0
	}
	for i := range s.decryptKey {
		s.decryptKey[i] = 0
	}
	for i := range s.noncePrefix {
		s.noncePrefix[i] = 0
	}
	s.established.Store(false)
}

// SessionManager manages multiple E2E sessions by session ID
type SessionManager struct {
	sessions sync.Map // map[string]*Session
}

// NewSessionManager creates a new session manager
func NewSessionManager() *SessionManager {
	return &SessionManager{}
}

// GetOrCreate returns existing session or creates new one
func (sm *SessionManager) GetOrCreate(sessionID string) *Session {
	if s, ok := sm.sessions.Load(sessionID); ok {
		return s.(*Session)
	}
	s := NewSession()
	actual, _ := sm.sessions.LoadOrStore(sessionID, s)
	return actual.(*Session)
}

// Get returns session if exists
func (sm *SessionManager) Get(sessionID string) (*Session, bool) {
	s, ok := sm.sessions.Load(sessionID)
	if !ok {
		return nil, false
	}
	return s.(*Session), true
}

// Remove deletes and zeros session
func (sm *SessionManager) Remove(sessionID string) {
	if s, ok := sm.sessions.LoadAndDelete(sessionID); ok {
		s.(*Session).Zero()
	}
}
