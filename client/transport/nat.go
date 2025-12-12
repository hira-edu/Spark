package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/stun/v3"
)

// NATType represents the detected NAT type
// Based on RFC 3489 NAT classification
type NATType int

const (
	// NATTypeUnknown means NAT type could not be determined
	NATTypeUnknown NATType = iota
	// NATTypeOpen means no NAT (public IP)
	NATTypeOpen
	// NATTypeFullCone means full cone NAT (1:1 mapping, any external host can send)
	NATTypeFullCone
	// NATTypeRestrictedCone means restricted cone NAT (1:1 mapping, only contacted hosts can send)
	NATTypeRestrictedCone
	// NATTypePortRestricted means port-restricted cone NAT (1:1 mapping, only contacted host:port can send)
	NATTypePortRestricted
	// NATTypeSymmetric means symmetric NAT (different mapping per destination) - hole punching fails
	NATTypeSymmetric
)

func (n NATType) String() string {
	switch n {
	case NATTypeOpen:
		return "Open"
	case NATTypeFullCone:
		return "FullCone"
	case NATTypeRestrictedCone:
		return "RestrictedCone"
	case NATTypePortRestricted:
		return "PortRestricted"
	case NATTypeSymmetric:
		return "Symmetric"
	default:
		return "Unknown"
	}
}

// CanHolePunch returns true if this NAT type supports TCP/UDP hole punching
func (n NATType) CanHolePunch() bool {
	switch n {
	case NATTypeOpen, NATTypeFullCone, NATTypeRestrictedCone, NATTypePortRestricted:
		return true
	default:
		return false
	}
}

// NATInfo contains the results of NAT detection
type NATInfo struct {
	Type         NATType
	ExternalIP   net.IP
	ExternalPort int
	LocalIP      net.IP
	LocalPort    int
	Latency      time.Duration
	DetectedAt   time.Time
}

// DefaultSTUNServers are public STUN servers for NAT detection
var DefaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun.cloudflare.com:3478",
	"stun.stunprotocol.org:3478",
}

// NATDetector detects NAT type using STUN
type NATDetector struct {
	stunServers []string
	timeout     time.Duration
	mu          sync.Mutex
	lastResult  *NATInfo
}

// NewNATDetector creates a new NAT detector
func NewNATDetector(stunServers []string) *NATDetector {
	if len(stunServers) == 0 {
		stunServers = DefaultSTUNServers
	}
	return &NATDetector{
		stunServers: stunServers,
		timeout:     5 * time.Second,
	}
}

// Detect performs NAT type detection using STUN
// Returns NATInfo with external IP/port and NAT type classification
func (d *NATDetector) Detect(ctx context.Context) (*NATInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Try multiple STUN servers to determine NAT type
	var results []stunResult
	var firstLatency time.Duration

	for i, server := range d.stunServers {
		if i >= 2 {
			// Only need 2 servers for symmetric NAT detection
			break
		}

		result, err := d.querySTUN(ctx, server)
		if err != nil {
			continue
		}

		if i == 0 {
			firstLatency = result.latency
		}
		results = append(results, result)
	}

	if len(results) == 0 {
		return &NATInfo{
			Type:       NATTypeUnknown,
			DetectedAt: time.Now(),
		}, fmt.Errorf("failed to contact any STUN server")
	}

	// Determine NAT type from results
	info := d.classifyNAT(ctx, results)
	info.Latency = firstLatency
	info.DetectedAt = time.Now()

	d.lastResult = info
	return info, nil
}

// stunResult holds the result from a single STUN query
type stunResult struct {
	serverAddr   string
	externalIP   net.IP
	externalPort int
	localIP      net.IP
	localPort    int
	latency      time.Duration
	otherAddr    *net.UDPAddr
}

// querySTUN queries a single STUN server for external IP/port
func (d *NATDetector) querySTUN(ctx context.Context, server string) (stunResult, error) {
	var result stunResult
	result.serverAddr = server

	// Create UDP connection
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return result, fmt.Errorf("listen UDP: %w", err)
	}
	defer conn.Close()

	// Get local address
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	result.localIP = localAddr.IP
	result.localPort = localAddr.Port

	// Resolve STUN server
	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return result, fmt.Errorf("resolve STUN server %s: %w", server, err)
	}

	// Build STUN binding request
	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)

	// Set deadline from context
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(d.timeout)
	}
	conn.SetDeadline(deadline)

	// Send request and measure latency
	start := time.Now()
	if _, err := conn.WriteToUDP(message.Raw, serverAddr); err != nil {
		return result, fmt.Errorf("send STUN request: %w", err)
	}

	// Read response
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return result, fmt.Errorf("read STUN response: %w", err)
	}
	result.latency = time.Since(start)

	// Parse response
	response := new(stun.Message)
	response.Raw = buf[:n]
	if err := response.Decode(); err != nil {
		return result, fmt.Errorf("decode STUN response: %w", err)
	}

	// Extract XOR-MAPPED-ADDRESS (RFC 5389) or MAPPED-ADDRESS (RFC 3489)
	var xorAddr stun.XORMappedAddress
	if err := xorAddr.GetFrom(response); err == nil {
		result.externalIP = xorAddr.IP
		result.externalPort = xorAddr.Port
		if otherAddr := extractOtherAddress(response); otherAddr != nil {
			result.otherAddr = otherAddr
		}
		return result, nil
	}

	// Fallback to MAPPED-ADDRESS for older servers
	var mappedAddr stun.MappedAddress
	if err := mappedAddr.GetFrom(response); err == nil {
		result.externalIP = mappedAddr.IP
		result.externalPort = mappedAddr.Port
		if otherAddr := extractOtherAddress(response); otherAddr != nil {
			result.otherAddr = otherAddr
		}
		return result, nil
	}

	return result, fmt.Errorf("no mapped address in STUN response")
}

func extractOtherAddress(msg *stun.Message) *net.UDPAddr {
	var other stun.OtherAddress
	if err := other.GetFrom(msg); err != nil {
		return nil
	}
	ip := make(net.IP, len(other.IP))
	copy(ip, other.IP)
	return &net.UDPAddr{
		IP:   ip,
		Port: other.Port,
	}
}

// classifyNAT determines NAT type from STUN results
// Uses RFC 3489 algorithm with filtering refinements when supported by the STUN server
func (d *NATDetector) classifyNAT(ctx context.Context, results []stunResult) *NATInfo {
	info := &NATInfo{}

	if len(results) == 0 {
		info.Type = NATTypeUnknown
		return info
	}

	// Get first result as primary
	primary := results[0]
	info.ExternalIP = primary.externalIP
	info.ExternalPort = primary.externalPort
	info.LocalIP = primary.localIP
	info.LocalPort = primary.localPort

	// Check if we have a public IP (no NAT)
	if primary.localIP.Equal(primary.externalIP) {
		info.Type = NATTypeOpen
		return info
	}

	// If we only got one result, assume cone NAT (optimistic)
	if len(results) < 2 {
		info.Type = NATTypeRestrictedCone
		return info
	}

	// Compare external addresses from different STUN servers
	// Symmetric NAT gives different external ports for different destinations
	secondary := results[1]

	if !primary.externalIP.Equal(secondary.externalIP) ||
		primary.externalPort != secondary.externalPort {
		// Different external address for different destinations = Symmetric NAT
		info.Type = NATTypeSymmetric
		return info
	}

	// Same external address for different destinations = Cone NAT
	if primary.serverAddr == "" || primary.otherAddr == nil {
		info.Type = NATTypeRestrictedCone
		return info
	}

	info.Type = d.determineConeSubtype(ctx, primary.serverAddr)
	return info
}

const (
	changeIPAndPort = 0x06
	changePortOnly  = 0x02
)

func (d *NATDetector) determineConeSubtype(ctx context.Context, server string) NATType {
	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return NATTypeRestrictedCone
	}

	if addr, err := d.runChangeRequest(ctx, server, changeIPAndPort); err == nil && addr != nil {
		if !addr.IP.Equal(serverAddr.IP) || addr.Port != serverAddr.Port {
			return NATTypeFullCone
		}
	}

	addr, err := d.runChangeRequest(ctx, server, changePortOnly)
	if err == nil && addr != nil {
		if addr.Port != serverAddr.Port {
			return NATTypeRestrictedCone
		}
		// Server ignored the change request, default to restricted cone
		return NATTypeRestrictedCone
	}

	return NATTypePortRestricted
}

func (d *NATDetector) runChangeRequest(ctx context.Context, server string, changeValue byte) (*net.UDPAddr, error) {
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	serverAddr, err := net.ResolveUDPAddr("udp4", server)
	if err != nil {
		return nil, err
	}

	message := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	message.Add(stun.AttrChangeRequest, []byte{0x00, 0x00, 0x00, changeValue})

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(d.timeout)
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.WriteToUDP(message.Raw, serverAddr); err != nil {
		return nil, err
	}

	buf := make([]byte, 1024)
	_, addr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}

	return addr, nil
}

// GetLastResult returns the cached NAT detection result
func (d *NATDetector) GetLastResult() *NATInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.lastResult
}

// DetectWithCache performs detection only if cache is stale
func (d *NATDetector) DetectWithCache(ctx context.Context, maxAge time.Duration) (*NATInfo, error) {
	d.mu.Lock()
	if d.lastResult != nil && time.Since(d.lastResult.DetectedAt) < maxAge {
		result := d.lastResult
		d.mu.Unlock()
		return result, nil
	}
	d.mu.Unlock()

	return d.Detect(ctx)
}

// QuickDetect performs a fast single-server detection (doesn't classify NAT fully)
// Useful when you just need the external IP/port quickly
func (d *NATDetector) QuickDetect(ctx context.Context) (*NATInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, server := range d.stunServers {
		result, err := d.querySTUN(ctx, server)
		if err != nil {
			continue
		}

		info := &NATInfo{
			ExternalIP:   result.externalIP,
			ExternalPort: result.externalPort,
			LocalIP:      result.localIP,
			LocalPort:    result.localPort,
			Latency:      result.latency,
			DetectedAt:   time.Now(),
		}

		// Quick classification: just check if local == external
		if result.localIP.Equal(result.externalIP) {
			info.Type = NATTypeOpen
		} else {
			info.Type = NATTypeUnknown // Would need full detection
		}

		return info, nil
	}

	return nil, fmt.Errorf("failed to contact any STUN server")
}
