package transport

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// HolePunchConfig configures TCP hole punching behavior
type HolePunchConfig struct {
	// LocalPort to bind for hole punching (0 = auto-assign)
	LocalPort int

	// PunchAttempts is the number of simultaneous connect attempts
	PunchAttempts int

	// PunchTimeout is the timeout for each punch attempt
	PunchTimeout time.Duration

	// RetryDelay is the delay between retry rounds
	RetryDelay time.Duration

	// MaxRetries is the maximum number of retry rounds
	MaxRetries int
}

// DefaultHolePunchConfig returns sensible defaults for TCP hole punching
func DefaultHolePunchConfig() *HolePunchConfig {
	return &HolePunchConfig{
		LocalPort:     0,
		PunchAttempts: 5,
		PunchTimeout:  3 * time.Second,
		RetryDelay:    500 * time.Millisecond,
		MaxRetries:    3,
	}
}

// HolePunchResult contains the result of a hole punching attempt
type HolePunchResult struct {
	Success      bool
	Conn         net.Conn
	LocalAddr    net.Addr
	RemoteAddr   net.Addr
	AttemptCount int
	Duration     time.Duration
	Error        error
}

// HolePuncher implements TCP hole punching for direct P2P connections
// Based on RustDesk's simultaneous TCP connect pattern
type HolePuncher struct {
	config    *HolePunchConfig
	localPort int
	mu        sync.Mutex
}

// NewHolePuncher creates a new TCP hole puncher
func NewHolePuncher(config *HolePunchConfig) *HolePuncher {
	if config == nil {
		config = DefaultHolePunchConfig()
	}
	return &HolePuncher{
		config:    config,
		localPort: config.LocalPort,
	}
}

// Punch attempts TCP hole punching to the peer's external address
// Both peers must call Punch() simultaneously for this to work
//
// How it works:
// 1. Both peers bind to a specific local port (using SO_REUSEADDR)
// 2. Both peers simultaneously send TCP SYN to each other's external IP:port
// 3. The first SYN packet "punches" a hole in the NAT by creating an outbound mapping
// 4. The peer's incoming SYN uses the same hole (NAT sees it as part of the session)
// 5. TCP handshake completes through the hole
func (h *HolePuncher) Punch(ctx context.Context, peerAddr *net.TCPAddr) (*HolePunchResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	result := &HolePunchResult{}
	startTime := time.Now()

	// Determine local address to bind
	localAddr := &net.TCPAddr{
		IP:   net.IPv4zero,
		Port: h.localPort,
	}

	// Try multiple rounds of simultaneous connects
	for retry := 0; retry <= h.config.MaxRetries; retry++ {
		if retry > 0 {
			select {
			case <-ctx.Done():
				result.Error = ctx.Err()
				return result, result.Error
			case <-time.After(h.config.RetryDelay):
			}
		}

		conn, err := h.attemptPunch(ctx, localAddr, peerAddr)
		result.AttemptCount++

		if err == nil {
			result.Success = true
			result.Conn = conn
			result.LocalAddr = conn.LocalAddr()
			result.RemoteAddr = conn.RemoteAddr()
			result.Duration = time.Since(startTime)
			return result, nil
		}

		// Update local port from first attempt for consistency
		if retry == 0 && localAddr.Port == 0 {
			// Try to extract port from error context or just continue
		}
	}

	result.Duration = time.Since(startTime)
	result.Error = fmt.Errorf("hole punch failed after %d attempts", result.AttemptCount)
	return result, result.Error
}

// attemptPunch makes simultaneous TCP connect attempts
func (h *HolePuncher) attemptPunch(ctx context.Context, localAddr, peerAddr *net.TCPAddr) (net.Conn, error) {
	// Create a context with timeout for this attempt
	attemptCtx, cancel := context.WithTimeout(ctx, h.config.PunchTimeout)
	defer cancel()

	// Channel to receive the first successful connection
	resultCh := make(chan net.Conn, h.config.PunchAttempts)
	var attempts int32
	var wg sync.WaitGroup

	// Launch multiple simultaneous connect attempts
	for i := 0; i < h.config.PunchAttempts; i++ {
		wg.Add(1)
		go func(attemptNum int) {
			defer wg.Done()

			conn, err := h.dialWithReuse(attemptCtx, localAddr, peerAddr)
			if err != nil {
				atomic.AddInt32(&attempts, 1)
				return
			}

			// Non-blocking send - first one wins
			select {
			case resultCh <- conn:
			default:
				// Another goroutine already succeeded, close this connection
				conn.Close()
			}
		}(i)

		// Small stagger between attempts to increase success rate
		time.Sleep(50 * time.Millisecond)
	}

	// Wait for first success or all failures
	go func() {
		wg.Wait()
		close(resultCh)
	}()

	select {
	case conn := <-resultCh:
		if conn != nil {
			return conn, nil
		}
		return nil, fmt.Errorf("all %d attempts failed", h.config.PunchAttempts)
	case <-attemptCtx.Done():
		return nil, attemptCtx.Err()
	}
}

// dialWithReuse creates a TCP connection with SO_REUSEADDR set
// This allows multiple connections from the same local port
func (h *HolePuncher) dialWithReuse(ctx context.Context, localAddr, remoteAddr *net.TCPAddr) (net.Conn, error) {
	// Create raw socket with SO_REUSEADDR
	dialer := &net.Dialer{
		LocalAddr: localAddr,
		Control: func(network, address string, c syscall.RawConn) error {
			var sysErr error
			err := c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR - crucial for hole punching
				sysErr = setReuseAddr(fd)
				if sysErr != nil {
					return
				}
				// Also set SO_REUSEPORT on platforms that support it
				// This allows multiple sockets to bind to the same port
				_ = setReusePort(int(fd))
			})
			if err != nil {
				return err
			}
			return sysErr
		},
	}

	return dialer.DialContext(ctx, "tcp", remoteAddr.String())
}

// PunchAsync performs hole punching asynchronously
// Useful when coordinating with rendezvous server timing
func (h *HolePuncher) PunchAsync(ctx context.Context, peerAddr *net.TCPAddr) <-chan *HolePunchResult {
	resultCh := make(chan *HolePunchResult, 1)

	go func() {
		result, _ := h.Punch(ctx, peerAddr)
		resultCh <- result
		close(resultCh)
	}()

	return resultCh
}

// GetBoundPort returns the port being used for hole punching
// Returns 0 if not yet bound
func (h *HolePuncher) GetBoundPort() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.localPort
}

// SetLocalPort sets the local port for hole punching
// Must be called before Punch()
func (h *HolePuncher) SetLocalPort(port int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.localPort = port
}

// PunchBidirectional attempts hole punching while also listening for incoming connections
// This increases success rate by handling both connect() and accept() scenarios
func (h *HolePuncher) PunchBidirectional(ctx context.Context, peerAddr *net.TCPAddr) (*HolePunchResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	result := &HolePunchResult{}
	startTime := time.Now()

	// Determine local address
	localAddr := &net.TCPAddr{
		IP:   net.IPv4zero,
		Port: h.localPort,
	}

	// Create listener with SO_REUSEADDR
	listener, listenPort, err := h.createReuseListener(localAddr)
	if err != nil {
		result.Error = fmt.Errorf("create listener: %w", err)
		return result, result.Error
	}
	defer listener.Close()

	// Update local port for outbound connections
	localAddr.Port = listenPort

	// Channel for results
	connCh := make(chan net.Conn, 2)
	errCh := make(chan error, 2)

	// Start listener goroutine
	go func() {
		listener.SetDeadline(time.Now().Add(h.config.PunchTimeout))
		conn, err := listener.Accept()
		if err != nil {
			errCh <- err
			return
		}
		connCh <- conn
	}()

	// Start connect goroutine
	go func() {
		conn, err := h.attemptPunch(ctx, localAddr, peerAddr)
		if err != nil {
			errCh <- err
			return
		}
		connCh <- conn
	}()

	// Wait for first success
	select {
	case conn := <-connCh:
		result.Success = true
		result.Conn = conn
		result.LocalAddr = conn.LocalAddr()
		result.RemoteAddr = conn.RemoteAddr()
		result.Duration = time.Since(startTime)
		return result, nil
	case <-ctx.Done():
		result.Error = ctx.Err()
		result.Duration = time.Since(startTime)
		return result, result.Error
	case <-time.After(h.config.PunchTimeout * time.Duration(h.config.MaxRetries+1)):
		result.Error = fmt.Errorf("bidirectional punch timeout")
		result.Duration = time.Since(startTime)
		return result, result.Error
	}
}

// createReuseListener creates a TCP listener with SO_REUSEADDR
func (h *HolePuncher) createReuseListener(localAddr *net.TCPAddr) (*net.TCPListener, int, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sysErr error
			err := c.Control(func(fd uintptr) {
				sysErr = setReuseAddr(fd)
				if sysErr != nil {
					return
				}
				_ = setReusePort(int(fd))
			})
			if err != nil {
				return err
			}
			return sysErr
		},
	}

	listener, err := lc.Listen(context.Background(), "tcp", localAddr.String())
	if err != nil {
		return nil, 0, err
	}

	tcpListener := listener.(*net.TCPListener)
	port := tcpListener.Addr().(*net.TCPAddr).Port

	return tcpListener, port, nil
}

// CoordinatedPunch performs hole punching with timing coordination
// startTime should be agreed upon via rendezvous server
func (h *HolePuncher) CoordinatedPunch(ctx context.Context, peerAddr *net.TCPAddr, startTime time.Time) (*HolePunchResult, error) {
	// Wait until start time
	waitDuration := time.Until(startTime)
	if waitDuration > 0 {
		select {
		case <-ctx.Done():
			return &HolePunchResult{Error: ctx.Err()}, ctx.Err()
		case <-time.After(waitDuration):
		}
	}

	// Both peers start punching at the same time
	return h.PunchBidirectional(ctx, peerAddr)
}
