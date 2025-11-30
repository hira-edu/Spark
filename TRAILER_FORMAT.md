# Spark Client Configuration Trailer Format

## Overview

Spark uses a **binary trailer approach** for embedding client configuration into executable binaries. This design is inspired by Sliver and other modern C2 frameworks, providing a robust, cross-platform solution that works identically across Windows, Linux, and macOS.

## Why Trailer-Based Embedding?

The trailer pattern offers several advantages over alternative approaches:

1. **Platform-Independent**: Works identically across Windows PE, Linux ELF, and macOS Mach-O binaries
2. **Immutable Templates**: Base executables remain unchanged and can be signed/verified
3. **No Binary Patching**: Avoids complex PE/ELF section manipulation or linker dependencies
4. **Simple Implementation**: Straightforward append/read operations with integrity checking
5. **Single-File Distribution**: No external configuration files or multi-file bundles required
6. **Update-Friendly**: Configuration can be updated without recompiling the base binary

## Binary Structure

```
┌─────────────────────────────────────────────────────────┐
│                    CLIENT BINARY                         │
├─────────────────────────────────────────────────────────┤
│  Original Compiled Code                                  │
│  (Clean template from releases/built/)                   │
│  Platform-specific executable (PE/ELF/Mach-O)           │
├─────────────────────────────────────────────────────────┤
│  Config Payload (384 bytes - Fixed Size)                │
│  ┌───────────────────────────────────────────────────┐  │
│  │ [0-1]    Length (uint16 big-endian)              │  │
│  │          - Actual data length (key + encrypted)   │  │
│  │                                                    │  │
│  │ [2-17]   AES Key (16 bytes)                       │  │
│  │          - Random key for this binary instance    │  │
│  │                                                    │  │
│  │ [18-N]   Encrypted JSON Config                    │  │
│  │          - AES-CTR encrypted configuration        │  │
│  │          - First 16 bytes: MD5 IV                 │  │
│  │          - Remaining: encrypted JSON data         │  │
│  │                                                    │  │
│  │ [N-383]  Random Padding                           │  │
│  │          - Filled with random UUIDs               │  │
│  │          - Prevents size-based fingerprinting     │  │
│  └───────────────────────────────────────────────────┘  │
├─────────────────────────────────────────────────────────┤
│  Trailer Footer (20 bytes - Fixed Size)                 │
│  ┌───────────────────────────────────────────────────┐  │
│  │ Magic:    "SPARKCFG" (8 bytes ASCII)             │  │
│  │           - Identifies Spark config trailer       │  │
│  │                                                    │  │
│  │ Version:  1 (uint16 little-endian)               │  │
│  │           - Format version for future changes     │  │
│  │                                                    │  │
│  │ Reserved: 0 (uint16 little-endian)               │  │
│  │           - Reserved for future use               │  │
│  │                                                    │  │
│  │ Length:   384 (uint32 little-endian)             │  │
│  │           - Size of config payload                │  │
│  │                                                    │  │
│  │ CRC32:    Checksum (uint32 little-endian)        │  │
│  │           - IEEE CRC32 of payload                 │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## Format Specifications

### Trailer Footer (20 bytes)

| Offset | Size | Type   | Endianness | Field    | Value       | Description                    |
|--------|------|--------|------------|----------|-------------|--------------------------------|
| 0      | 8    | string | N/A        | Magic    | "SPARKCFG"  | Magic identifier               |
| 8      | 2    | uint16 | Little     | Version  | 1           | Format version                 |
| 10     | 2    | uint16 | Little     | Reserved | 0           | Reserved for future use        |
| 12     | 4    | uint32 | Little     | Length   | 384         | Payload size in bytes          |
| 16     | 4    | uint32 | Little     | CRC32    | Calculated  | IEEE CRC32 checksum of payload |

**Constants (defined in `client/config/config.go`):**
```go
const (
    TrailerMagic      = "SPARKCFG"
    trailerVersion    = uint16(1)
    TrailerFooterSize = 20
    ConfigBufferSize  = 384
)
```

### Config Payload (384 bytes)

| Offset | Size      | Type   | Endianness | Field          | Description                          |
|--------|-----------|--------|------------|----------------|--------------------------------------|
| 0      | 2         | uint16 | Big        | Data Length    | Length of (Key + Encrypted Data)     |
| 2      | 16        | bytes  | N/A        | AES Key        | Random 16-byte encryption key        |
| 18     | Variable  | bytes  | N/A        | Encrypted Data | AES-CTR encrypted JSON configuration |
| N      | 384-N     | bytes  | N/A        | Padding        | Random padding to fill 384 bytes     |

**Note on Endianness:**
- Footer uses **little-endian** (matches binary.LittleEndian in Go)
- Payload length prefix uses **big-endian** (network byte order)

## Configuration JSON Schema

The decrypted payload contains JSON with the following structure:

```json
{
  "secure": true,
  "host": "c2.example.com",
  "port": 443,
  "path": "/ws",
  "uuid": "0123456789abcdef0123456789abcdef",
  "key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

**Field Descriptions:**

- `secure` (bool): Use TLS/SSL (wss:// vs ws://)
- `host` (string): Server hostname or IP address
- `port` (int): Server port number
- `path` (string): WebSocket endpoint path
- `uuid` (string): Hex-encoded client UUID (32 characters = 16 bytes)
- `key` (string): Hex-encoded client authentication key (64 characters = 32 bytes)

## Encryption Details

### Payload Encryption (AES-128-CTR)

**Encryption Process (Server-side in `genConfig()`):**

1. Marshal configuration struct to JSON
2. Generate random 16-byte AES key
3. Encrypt JSON using AES-CTR:
   - Key: 16-byte random key
   - IV: MD5 hash of plaintext (first 16 bytes)
   - Mode: CTR (Counter Mode)
4. Prepend MD5 IV to encrypted data: `[MD5(16)][Encrypted Data]`
5. Prepend encryption key: `[Key(16)][MD5(16)][Encrypted Data]`
6. Prepend big-endian length: `[Length(2)][Key(16)][MD5(16)][Encrypted Data]`
7. Pad to 384 bytes with random UUIDs

**Decryption Process (Client-side in `decrypt()`):**

1. Extract 2-byte big-endian length
2. Extract 16-byte key
3. Extract encrypted data (includes MD5 IV)
4. Decrypt using AES-CTR:
   - Key: Extracted 16-byte key
   - IV: First 16 bytes of encrypted data (MD5 hash)
   - Mode: CTR
5. Verify MD5 hash of decrypted data matches IV
6. Return decrypted JSON

**Implementation:**
```go
// Encryption (server/common/common.go)
func EncAES(data []byte, key []byte) ([]byte, error) {
    block, _ := aes.NewCipher(key)
    hash, _ := utils.GetMD5(data)
    stream := cipher.NewCTR(block, hash)
    buffer := make([]byte, len(data))
    stream.XORKeyStream(buffer, data)
    return append(hash, buffer...), nil
}

// Decryption (client/client.go)
func decrypt(data []byte, key []byte) ([]byte, error) {
    block, _ := aes.NewCipher(key)
    stream := cipher.NewCTR(block, data[:16])  // First 16 bytes = MD5 IV
    decBuffer := make([]byte, len(data)-16)
    stream.XORKeyStream(decBuffer, data[16:])
    hash, _ := utils.GetMD5(decBuffer)
    if !bytes.Equal(hash, data[:16]) {
        return nil, errors.New("verification failed")
    }
    return decBuffer, nil
}
```

### Client Credential Derivation

When generating a client, the server creates unique credentials:

```go
// Generate random 16-byte UUID
clientUUID := utils.GetUUID()

// Derive authentication key by encrypting UUID with server salt
clientKey, _ := common.EncAES(clientUUID, servercfg.Config.SaltBytes)
```

**Client Authentication:**
1. Client sends UUID and Key in WebSocket handshake headers
2. Server decrypts Key using server salt
3. Verification succeeds if `DecAES(clientKey, serverSalt) == clientUUID`

## Generation Workflow

### Server-Side Generation

**File:** `server/handler/generate/generate.go`

```go
func GenerateClient(ctx *gin.Context) {
    // 1. Open clean binary template
    tpl, _ := os.Open(fmt.Sprintf(servercfg.BuiltPath, form.OS, form.Arch))

    // 2. Generate client credentials
    clientUUID := utils.GetUUID()
    clientKey, _ := common.EncAES(clientUUID, servercfg.Config.SaltBytes)

    // 3. Create config payload (384 bytes)
    cfgBytes, _ := genConfig(clientCfg{
        Secure: form.Secure == "true",
        Host:   form.Host,
        Port:   int(form.Port),
        Path:   form.Path,
        UUID:   hex.EncodeToString(clientUUID),
        Key:    hex.EncodeToString(clientKey),
    })

    // 4. Build trailer footer (20 bytes)
    trailerFooter := clientcfg.BuildTrailerFooter(cfgBytes)

    // 5. Stream to client: [template][payload][footer]
    total := templateSize + 384 + 20
    ctx.Header("Content-Length", strconv.FormatInt(total, 10))
    io.Copy(ctx.Writer, tpl)
    ctx.Writer.Write(cfgBytes)
    ctx.Writer.Write(trailerFooter)
}
```

### Client-Side Reading

**File:** `client/config/config.go`

```go
func readTrailerFromPath(path string) ([]byte, error) {
    file, _ := os.Open(path)
    stat, _ := file.Stat()

    // 1. Read last 20 bytes (footer)
    footerOffset := stat.Size() - TrailerFooterSize
    buf := make([]byte, TrailerFooterSize)
    file.ReadAt(buf, footerOffset)

    // 2. Parse footer structure
    var footer trailerFooter
    binary.Read(bytes.NewReader(buf), binary.LittleEndian, &footer)

    // 3. Validate magic and version
    if string(footer.Magic[:]) != TrailerMagic {
        return nil, errors.New("magic mismatch")
    }
    if footer.Version != trailerVersion {
        return nil, errors.New("version mismatch")
    }

    // 4. Read payload based on footer length
    length := int64(footer.Length)
    data := make([]byte, length)
    file.ReadAt(data, footerOffset-length)

    // 5. Verify CRC32 checksum
    if crc32.ChecksumIEEE(data) != footer.CRC32 {
        return nil, errors.New("checksum mismatch")
    }

    return data, nil
}
```

### Client Initialization

**File:** `client/client.go`

```go
func init() {
    // 1. Read 384-byte encrypted payload from trailer
    rawBuffer, _ := config.RawConfig()

    // 2. Extract length (first 2 bytes, big-endian)
    dataLen := int(binary.BigEndian.Uint16(rawBuffer[:2]))

    // 3. Extract key (16 bytes) and encrypted data
    cfgBytes := rawBuffer[2 : 2+dataLen]
    key := cfgBytes[:16]
    encrypted := cfgBytes[16:]

    // 4. Decrypt configuration
    cfgBytes, _ = decrypt(encrypted, key)

    // 5. Unmarshal JSON into config struct
    utils.JSON.Unmarshal(cfgBytes, &config.Config)
}
```

## Auto-Update Mechanism

Spark clients can self-update while preserving their configuration.

**Update Process:**

1. Client sends current commit hash + raw config to `/api/client/update`
2. Server checks if client is outdated
3. If update needed, server streams:
   - New binary template
   - Client's existing config payload (from request body)
   - New trailer footer
4. Client writes to `.tmp` file
5. Client executes new binary with `--update` flag
6. New process replaces old binary

**Server Handler:** `server/handler/utility/utility.go`

```go
func CheckUpdate(ctx *gin.Context) {
    // Client sends its current config in request body
    body, _ := ctx.GetRawData()  // 384-byte config

    // Stream updated binary with preserved config
    io.Copy(ctx.Writer, tpl)
    ctx.Writer.Write(body)
    ctx.Writer.Write(clientcfg.BuildTrailerFooter(body))
}
```

This ensures clients maintain their unique UUID/Key credentials across updates.

## Security Considerations

### Strengths

1. **Per-Binary Encryption**: Each client binary has a unique 16-byte AES key
2. **Integrity Checking**: CRC32 prevents accidental corruption
3. **Credential Derivation**: Client keys are derived from server salt
4. **Size Obfuscation**: Random padding prevents configuration length fingerprinting
5. **Version Control**: Footer version field allows format evolution

### Limitations

1. **CRC32 is not HMAC**: CRC32 provides integrity but not authentication
   - An attacker who can modify the binary can also update the CRC32
   - Consider upgrading to HMAC-SHA256 if authentication is required

2. **Config Encryption Key in Payload**: The 16-byte key is stored with the encrypted data
   - This is acceptable for obfuscation but not true confidentiality
   - An analyst can extract and decrypt the config from a binary

3. **MD5 for IV**: MD5 is deprecated for security purposes
   - Used here for integrity checking, not cryptographic security
   - Consider SHA-256 for future versions

4. **Static Analysis**: The trailer pattern is well-known
   - Security scanners can identify SPARKCFG magic bytes
   - Consider obfuscation if detection avoidance is required

### Recommended Improvements

For enhanced security, consider:

1. **HMAC Authentication**:
   ```go
   footer.HMAC = hmac.Sum256(payload, serverSecret)
   ```

2. **Encrypted Footer**:
   - Encrypt the entire footer with a server key
   - Prevents passive scanning for SPARKCFG magic

3. **Key Derivation Function**:
   - Use PBKDF2/Argon2 instead of direct encryption
   - Makes key extraction more computationally expensive

4. **Randomized Magic**:
   - XOR magic bytes with client UUID
   - Makes static signature detection harder

## Cross-Platform Compatibility

The trailer approach works identically across all platforms:

### Windows (PE)
- Appending data after PE sections is safe
- Windows loader ignores trailing bytes
- Works with code signing (signature in PE header, not affected by trailer)

### Linux (ELF)
- ELF loader only reads sections defined in program headers
- Trailing bytes are ignored
- No impact on executable behavior

### macOS (Mach-O)
- Similar to ELF, loader only reads defined segments
- Trailing data is ignored
- Compatible with codesigning (signatures are in LC_CODE_SIGNATURE segment)

**Key Advantage:** One codebase, one implementation, works everywhere.

## Comparison with Alternative Approaches

### Placeholder Replacement (Old Method)

**How it works:**
- Embed unique placeholder bytes in binary
- Search and replace with configuration at generation time

**Problems:**
- Brittle: Compiler optimization can split/move placeholders
- Platform-specific: Different behavior across PE/ELF/Mach-O
- Size-limited: Must pre-allocate exact space
- Signature-breaking: Modifications invalidate code signatures

**Why Spark moved away:** Unreliable and hard to maintain.

### PE/ELF Section Manipulation (Meterpreter-style)

**How it works:**
- Add configuration as a new section in executable format
- Requires parsing and modifying binary headers

**Problems:**
- Platform-specific: Separate code for PE vs ELF vs Mach-O
- Complex: Requires binary format expertise
- Library dependencies: Need parsing libraries for each format
- Size changes: May require adjusting section alignments

**Why trailer is better:** Simpler, cross-platform, no format knowledge needed.

### External Configuration Files

**How it works:**
- Ship configuration as separate file
- Client reads config at runtime

**Problems:**
- Multi-file distribution: Complicates deployment
- Fragile: Config file can be lost or separated from binary
- Obvious: Configuration is plainly visible in filesystem
- Not self-contained: Requires bundling/installer

**Why trailer is better:** Single-file distribution, self-contained.

## File Locations

### Client Code
- **Config Reading**: `client/config/config.go`
  - `RawConfig()` - Entry point
  - `readTrailer()` - Reads from executable
  - `readTrailerFromPath()` - Core reading logic
  - `BuildTrailerFooter()` - Creates footer structure

- **Initialization**: `client/client.go`
  - `init()` - Loads and decrypts config
  - `decrypt()` - AES-CTR decryption

### Server Code
- **Generation**: `server/handler/generate/generate.go`
  - `GenerateClient()` - HTTP handler for client download
  - `genConfig()` - Creates encrypted payload
  - `CheckClient()` - Validates config size

- **Updates**: `server/handler/utility/utility.go`
  - `CheckUpdate()` - Auto-update endpoint
  - Preserves existing config during updates

### Templates
- **Location**: `releases/built/`
- **Formats**:
  - `windows_amd64.exe`, `windows_386.exe`, `windows_arm64.exe`
  - `linux_amd64`, `linux_386`, `linux_arm`, `linux_arm64`
  - `darwin_amd64`, `darwin_arm64`

**Important:** These are clean binaries without any embedded configuration.

## Testing and Validation

### Verify Trailer Integrity

```bash
# Check if binary has trailer
tail -c 20 client.exe | xxd
# Should show: 53 50 41 52 4b 43 46 47 (SPARKCFG magic)

# Extract footer
tail -c 20 client.exe > footer.bin

# Extract payload (assuming 384-byte payload)
tail -c 404 client.exe | head -c 384 > payload.bin

# Verify CRC32 (using Python)
python3 -c "
import zlib
data = open('payload.bin', 'rb').read()
footer = open('footer.bin', 'rb').read()
crc_expected = int.from_bytes(footer[16:20], 'little')
crc_actual = zlib.crc32(data)
print(f'Expected: {crc_expected:08x}')
print(f'Actual:   {crc_actual:08x}')
print(f'Valid:    {crc_expected == crc_actual}')
"
```

### Test Generation

```bash
# Generate test client via API
curl -X POST http://localhost:8000/api/client/generate \
  -H "Content-Type: application/json" \
  -d '{
    "os": "linux",
    "arch": "amd64",
    "host": "test.example.com",
    "port": 443,
    "path": "/ws",
    "secure": "true"
  }' \
  --output client-test

# Verify trailer exists
tail -c 20 client-test | xxd
```

### Debugging Client Config Loading

Add logging to `client/client.go`:

```go
func init() {
    rawBuffer, err := config.RawConfig()
    log.Printf("RawConfig length: %d, error: %v", len(rawBuffer), err)

    dataLen := int(binary.BigEndian.Uint16(rawBuffer[:2]))
    log.Printf("Config data length: %d", dataLen)

    cfgBytes := rawBuffer[2 : 2+dataLen]
    log.Printf("Encrypted config: %x", cfgBytes[:32])

    cfgBytes, err = decrypt(cfgBytes[16:], cfgBytes[:16])
    log.Printf("Decrypted JSON: %s", string(cfgBytes))
}
```

## Future Enhancements

### Version 2 Considerations

If `trailerVersion` is incremented to 2, possible improvements:

1. **Variable Payload Size**:
   - Remove fixed 384-byte limitation
   - Allow footer.Length to specify any size
   - More efficient for small configs

2. **HMAC Authentication**:
   ```go
   type trailerFooterV2 struct {
       Magic    [8]byte
       Version  uint16   // = 2
       Reserved uint16
       Length   uint32
       HMAC     [32]byte // SHA-256 HMAC
   }
   ```

3. **Compression**:
   - Compress JSON before encryption
   - Add compression flag to footer

4. **Multi-Config Support**:
   - Support fallback servers
   - Multiple C2 endpoints in single binary

5. **Obfuscated Magic**:
   - XOR magic with UUID or timestamp
   - Harder to detect via static analysis

**Migration Path:**
- Client checks `footer.Version` field
- Supports both v1 and v2 simultaneously
- Gradual rollout without breaking existing clients

## Conclusion

The trailer-based configuration embedding in Spark represents a **battle-tested, robust approach** used by professional C2 frameworks like Sliver. It provides:

- **Simplicity**: Easy to implement and maintain
- **Reliability**: No dependency on compiler behavior or binary format details
- **Portability**: Works identically across all platforms
- **Maintainability**: Clean separation between base binary and configuration

This design prioritizes **operational robustness** over maximum security, which is appropriate for a C2 framework where the binary is already a sensitive artifact. The integrity checking prevents accidental corruption, while the per-binary encryption provides basic obfuscation.

For environments requiring higher security, the format can be extended (via version field) to add HMAC authentication, stronger KDFs, or other enhancements without breaking backwards compatibility.

## References

- [Sliver C2 Framework](https://github.com/BishopFox/sliver) - Similar trailer approach
- [Metasploit Meterpreter](https://github.com/rapid7/metasploit-payloads) - PE section approach
- [Cobalt Strike](https://www.cobaltstrike.com/) - Stageless payload embedding
- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [ELF Format Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [Mach-O Format](https://developer.apple.com/documentation/kernel/mach-o)
