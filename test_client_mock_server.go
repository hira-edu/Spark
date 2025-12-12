//go:build mockserver
// +build mockserver

// Mock desktop server for E2E testing - pairs with test_client.go
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
)

// runStandaloneMockServer hosts a lightweight desktop streaming server that speaks the
// same binary protocol as Rocket devices. This allows the Playwright E2E suite to drive
// the browser without requiring a real agent.
func runStandaloneMockServer(port, width, height, fps int) {
	server := newStandaloneMockServer(width, height, fps)
	addr := fmt.Sprintf(":%d", port)

	mux := http.NewServeMux()
	mux.HandleFunc("/mock-desktop", server.handleWebSocket)
	mux.HandleFunc("/mock/health", server.handleHealth)
	mux.HandleFunc("/mock/init", server.handleInit)
	mux.HandleFunc("/mock/resolution", server.handleResolution)
	mux.HandleFunc("/mock/frame", server.handleFrame)
	mux.HandleFunc("/mock/pong", server.handlePong)
	mux.HandleFunc("/mock/cursor", server.handleCursor)
	mux.HandleFunc("/mock/auto", server.handleAuto)
	mux.HandleFunc("/mock/reset", server.handleReset)
	mux.HandleFunc("/mock/events", server.handleEvents)
	mux.HandleFunc("/mock/disconnect", server.handleDisconnect)

	httpServer := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-stop
		fmt.Println("[MockDesktop] Shutting down...")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
	}()

	fmt.Printf("[MockDesktop] Standalone server listening on %s\n", addr)
	fmt.Println("[MockDesktop]  - WS endpoint:   ws://127.0.0.1" + addr + "/mock-desktop")
	fmt.Println("[MockDesktop]  - Control API:   http://127.0.0.1" + addr + "/mock/*")
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fmt.Printf("[MockDesktop] Server error: %v\n", err)
	}
}

type standaloneMockServer struct {
	mu          sync.RWMutex
	writeMu     sync.Mutex
	clients     map[*websocket.Conn]struct{}
	width       int
	height      int
	fps         int
	inputEvents []map[string]any
	frameSeq    uint32
	frameTicker *time.Ticker
	stopTicker  chan struct{}
}

func newStandaloneMockServer(width, height, fps int) *standaloneMockServer {
	if width <= 0 {
		width = 1280
	}
	if height <= 0 {
		height = 720
	}
	if fps <= 0 {
		fps = 10
	}
	return &standaloneMockServer{
		clients: make(map[*websocket.Conn]struct{}),
		width:   width,
		height:  height,
		fps:     fps,
	}
}

func (s *standaloneMockServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("[MockDesktop] Upgrade failed: %v\n", err)
		return
	}

	s.mu.Lock()
	s.clients[conn] = struct{}{}
	clientCount := len(s.clients)
	s.mu.Unlock()

	fmt.Printf("[MockDesktop] Client connected (total=%d)\n", clientCount)

	// Send initial packets
	s.sendInit(conn)
	s.sendResolution(conn, s.width, s.height)
	s.sendFrame(conn, frameOptions{})

	// Start reader loop
	go s.readLoop(conn)
}

func (s *standaloneMockServer) handleHealth(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	resp := map[string]any{
		"status":      "ok",
		"clients":     len(s.clients),
		"width":       s.width,
		"height":      s.height,
		"auto_frames": s.frameTicker != nil,
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, resp)
}

func (s *standaloneMockServer) handleInit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Width  int `json:"width"`
		Height int `json:"height"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Width <= 0 {
		req.Width = s.width
	}
	if req.Height <= 0 {
		req.Height = s.height
	}
	s.mu.Lock()
	s.width = req.Width
	s.height = req.Height
	s.mu.Unlock()
	s.broadcastInit()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *standaloneMockServer) handleResolution(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Width  int `json:"width"`
		Height int `json:"height"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Width > 0 && req.Height > 0 {
		s.mu.Lock()
		s.width = req.Width
		s.height = req.Height
		s.mu.Unlock()
	}
	s.broadcastResolution(req.Width, req.Height)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *standaloneMockServer) handleFrame(w http.ResponseWriter, r *http.Request) {
	var req frameOptions
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	s.broadcastFrame(req)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *standaloneMockServer) handlePong(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source string `json:"source"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Source == "" {
		req.Source = "device"
	}
	packet := Packet{
		Act: "DESKTOP_PONG",
		Data: map[string]any{
			"source": req.Source,
		},
	}
	s.broadcastJSON(packet)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *standaloneMockServer) handleCursor(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	packet := Packet{
		Act:  "CURSOR_UPDATE",
		Data: req,
	}
	s.broadcastJSON(packet)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *standaloneMockServer) handleAuto(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled    bool   `json:"enabled"`
		IntervalMS int    `json:"interval_ms"`
		Color      string `json:"color"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}

	if !req.Enabled {
		s.stopAutoFrames()
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}

	interval := time.Second / time.Duration(s.fps)
	if req.IntervalMS > 0 {
		interval = time.Duration(req.IntervalMS) * time.Millisecond
	}
	color := parseHexColor(req.Color)
	s.startAutoFrames(interval, color)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *standaloneMockServer) handleReset(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	s.inputEvents = nil
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *standaloneMockServer) handleEvents(w http.ResponseWriter, _ *http.Request) {
	s.mu.RLock()
	events := make([]map[string]any, len(s.inputEvents))
	copy(events, s.inputEvents)
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"events": events})
}

func (s *standaloneMockServer) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code   int    `json:"code"`
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, err)
		return
	}
	if req.Code == 0 {
		req.Code = websocket.CloseNormalClosure
	}
	if req.Reason == "" {
		req.Reason = "mock disconnect"
	}
	s.mu.RLock()
	for conn := range s.clients {
		_ = conn.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(req.Code, req.Reason), time.Now().Add(time.Second))
	}
	s.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *standaloneMockServer) readLoop(conn *websocket.Conn) {
	defer s.removeClient(conn)
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure) {
				fmt.Printf("[MockDesktop] Read error: %v\n", err)
			}
			return
		}
		if mt != websocket.BinaryMessage {
			continue
		}
		s.handleIncoming(conn, data)
	}
}

func (s *standaloneMockServer) handleIncoming(conn *websocket.Conn, data []byte) {
	if len(data) < 8 {
		return
	}
	if string(data[:4]) != magicDesktop {
		return
	}
	op := data[5]
	if op != opJSON {
		return
	}
	bodyLen := int(binary.BigEndian.Uint16(data[6:8]))
	if len(data) < 8+bodyLen {
		return
	}
	var pack Packet
	if err := json.Unmarshal(data[8:8+bodyLen], &pack); err != nil {
		fmt.Printf("[MockDesktop] Failed to parse control packet: %v\n", err)
		return
	}

	switch strings.ToUpper(pack.Act) {
	case "DESKTOP_PING":
		resp := Packet{
			Act: "DESKTOP_PONG",
			Data: map[string]any{
				"source": "device",
			},
		}
		s.writeJSONTo(conn, resp)
	case "DESKTOP_SHOT":
		s.sendFrame(conn, frameOptions{})
	case "DESKTOP_INPUT":
		s.recordInputEvents(pack.Data)
		resp := Packet{Act: "DESKTOP_INPUT", Code: 0}
		s.writeJSONTo(conn, resp)
	case "DESKTOP_CONFIG":
		resp := Packet{
			Act: "DESKTOP_CONFIG_ACK",
			Data: map[string]any{
				"updated": []string{"codec", "fps", "quality"},
				"width":   s.width,
				"height":  s.height,
			},
		}
		s.writeJSONTo(conn, resp)
	default:
		// Acknowledge other actions generically
		s.writeJSONTo(conn, Packet{Act: pack.Act, Code: 0})
	}
}

func (s *standaloneMockServer) recordInputEvents(data map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if events, ok := data["events"].([]any); ok {
		for _, evt := range events {
			if evtMap, ok := evt.(map[string]any); ok {
				s.inputEvents = append(s.inputEvents, evtMap)
				if len(s.inputEvents) > 200 {
					s.inputEvents = s.inputEvents[len(s.inputEvents)-200:]
				}
			}
		}
	}
}

func (s *standaloneMockServer) removeClient(conn *websocket.Conn) {
	s.mu.Lock()
	delete(s.clients, conn)
	remaining := len(s.clients)
	s.mu.Unlock()
	_ = conn.Close()
	fmt.Printf("[MockDesktop] Client disconnected (total=%d)\n", remaining)
}

func (s *standaloneMockServer) broadcastInit() {
	s.mu.RLock()
	defer s.mu.RUnlock()
	packet := Packet{
		Act: "DESKTOP_INIT",
		Data: map[string]any{
			"width":  s.width,
			"height": s.height,
			"monitors": []map[string]any{
				{
					"id":     0,
					"name":   "MockDisplay",
					"width":  s.width,
					"height": s.height,
				},
			},
		},
	}
	for conn := range s.clients {
		s.writeJSONTo(conn, packet)
	}
}

func (s *standaloneMockServer) broadcastResolution(width, height int) {
	if width <= 0 || height <= 0 {
		s.mu.RLock()
		width = s.width
		height = s.height
		s.mu.RUnlock()
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for conn := range s.clients {
		s.sendResolution(conn, width, height)
	}
}

func (s *standaloneMockServer) broadcastFrame(opts frameOptions) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for conn := range s.clients {
		s.sendFrame(conn, opts)
	}
}

func (s *standaloneMockServer) sendInit(conn *websocket.Conn) {
	packet := Packet{
		Act: "DESKTOP_INIT",
		Data: map[string]any{
			"width":  s.width,
			"height": s.height,
			"monitors": []map[string]any{
				{
					"id":     0,
					"name":   "MockDisplay",
					"width":  s.width,
					"height": s.height,
				},
			},
		},
	}
	s.writeJSONTo(conn, packet)
}

func (s *standaloneMockServer) sendResolution(conn *websocket.Conn, width, height int) {
	buf := make([]byte, frameHeaderLength+2+2+2)
	copy(buf[:4], []byte(magicDesktop))
	buf[4] = serviceDesktop
	buf[5] = opResolution
	eventID := make([]byte, 16)
	rand.Read(eventID)
	copy(buf[6:22], eventID)

	// Frame metadata (frameSeq=0 marks non-frame payloads like resolution updates)
	binary.BigEndian.PutUint32(buf[22:26], 0)
	binary.BigEndian.PutUint16(buf[26:28], 0)
	binary.BigEndian.PutUint16(buf[28:30], 1)

	binary.BigEndian.PutUint16(buf[30:32], 4)
	binary.BigEndian.PutUint16(buf[32:34], uint16(width))
	binary.BigEndian.PutUint16(buf[34:36], uint16(height))

	s.writeMu.Lock()
	_ = conn.WriteMessage(websocket.BinaryMessage, buf)
	s.writeMu.Unlock()
}

type frameOptions struct {
	Width  int    `json:"width"`
	Height int    `json:"height"`
	Color  string `json:"color"`
}

func (s *standaloneMockServer) sendFrame(conn *websocket.Conn, opts frameOptions) {
	width := opts.Width
	height := opts.Height
	if width <= 0 {
		width = 128
	}
	if height <= 0 {
		height = 128
	}
	fill := parseHexColor(opts.Color)

	img := image.NewRGBA(image.Rect(0, 0, width, height))
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			img.Set(x, y, fill)
		}
	}

	var jpegBuf bytes.Buffer
	_ = jpeg.Encode(&jpegBuf, img, &jpeg.Options{Quality: 70})

	blockBodyLen := 10 + jpegBuf.Len()
	blockBuf := make([]byte, blockBodyLen+2)
	binary.BigEndian.PutUint16(blockBuf[0:2], uint16(blockBodyLen))
	binary.BigEndian.PutUint16(blockBuf[2:4], 1) // JPEG
	binary.BigEndian.PutUint16(blockBuf[4:6], 0)
	binary.BigEndian.PutUint16(blockBuf[6:8], 0)
	binary.BigEndian.PutUint16(blockBuf[8:10], uint16(width))
	binary.BigEndian.PutUint16(blockBuf[10:12], uint16(height))
	copy(blockBuf[12:], jpegBuf.Bytes())

	frame := make([]byte, frameHeaderLength+len(blockBuf))
	copy(frame[:4], []byte(magicDesktop))
	frame[4] = serviceDesktop
	frame[5] = opFrameFirst
	eventID := make([]byte, 16)
	rand.Read(eventID)
	copy(frame[6:22], eventID)

	copy(frame[30:], blockBuf)

	s.writeMu.Lock()
	s.frameSeq++
	seq := s.frameSeq
	// Frame metadata (monotonic sequence per connection)
	binary.BigEndian.PutUint32(frame[22:26], seq)
	binary.BigEndian.PutUint16(frame[26:28], 0)
	binary.BigEndian.PutUint16(frame[28:30], 1)
	_ = conn.WriteMessage(websocket.BinaryMessage, frame)
	s.writeMu.Unlock()
}

func (s *standaloneMockServer) writeJSONTo(conn *websocket.Conn, pack Packet) {
	body, _ := json.Marshal(pack)
	buf := make([]byte, 4+1+1+len(body))
	copy(buf[:4], []byte(magicDesktop))
	buf[4] = serviceDesktop
	buf[5] = opJSON
	copy(buf[6:], body)
	s.writeMu.Lock()
	_ = conn.WriteMessage(websocket.BinaryMessage, buf)
	s.writeMu.Unlock()
}

func (s *standaloneMockServer) broadcastJSON(pack Packet) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for conn := range s.clients {
		s.writeJSONTo(conn, pack)
	}
}

func (s *standaloneMockServer) startAutoFrames(interval time.Duration, fill color.RGBA) {
	s.stopAutoFrames()
	s.frameTicker = time.NewTicker(interval)
	s.stopTicker = make(chan struct{})
	go func() {
		for {
			select {
			case <-s.frameTicker.C:
				s.broadcastFrame(frameOptions{
					Width:  s.width / 4,
					Height: s.height / 4,
					Color:  fmt.Sprintf("#%02x%02x%02x", fill.R, fill.G, fill.B),
				})
			case <-s.stopTicker:
				return
			}
		}
	}()
}

func (s *standaloneMockServer) stopAutoFrames() {
	if s.frameTicker != nil {
		s.frameTicker.Stop()
		s.frameTicker = nil
	}
	if s.stopTicker != nil {
		close(s.stopTicker)
		s.stopTicker = nil
	}
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]any{
		"error": err.Error(),
	})
}

func decodeJSON(r *http.Request, dest any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(r.Body)
	return dec.Decode(dest)
}

func parseHexColor(hexStr string) color.RGBA {
	if strings.HasPrefix(hexStr, "#") && len(hexStr) == 7 {
		var r, g, b uint64
		fmt.Sscanf(hexStr, "#%02x%02x%02x", &r, &g, &b)
		return color.RGBA{uint8(r), uint8(g), uint8(b), 255}
	}
	// Default accent color
	return color.RGBA{0x34, 0x78, 0xFF, 0xFF}
}
