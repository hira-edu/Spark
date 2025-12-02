package cluster

import (
	"Rocket/modules"
	"Rocket/server/common"
	"Rocket/server/storage"
	"Rocket/utils"
	"context"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// Config controls clustered/brokered behavior.
type Config struct {
	Enable           bool
	ControllerID     string
	ControllerIDFile string
	PublicURL        string
	LeaseTTL         time.Duration
	SessionLeaseTTL  time.Duration
	StaleAfter       time.Duration
	CleanupInterval  time.Duration
	UseChangeStreams bool
	PreferProxy      bool
	ProxyTimeout     time.Duration
}

type ctrlInfo struct {
	id        string
	publicURL string
}

type Manager struct {
	cfg          Config
	controllerID string
	publicURL    string

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	proxyMu sync.RWMutex
	proxies map[string]*httputil.ReverseProxy
	metrics struct {
		deviceClaims         atomic.Uint64
		redirects            atomic.Uint64
		proxied              atomic.Uint64
		reassignments        atomic.Uint64
		changeStreamRestarts atomic.Uint64
	}
}

var (
	manager   *Manager
	managerMu sync.RWMutex
)

// Init creates and starts the global cluster manager. If clustering is disabled
// or MongoDB is not available, it returns nil without error.
func Init(cfg Config) (*Manager, error) {
	if !cfg.Enable || !storage.IsMongoEnabled() {
		return nil, nil
	}

	cfg = applyDefaults(cfg)

	controllerID, err := resolveControllerID(cfg.ControllerIDFile, cfg.ControllerID)
	if err != nil {
		return nil, err
	}
	cfg.ControllerID = controllerID

	m := &Manager{
		cfg:          cfg,
		controllerID: controllerID,
		publicURL:    strings.TrimSuffix(cfg.PublicURL, "/"),
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())

	// Expose controller ID globally for other packages.
	common.SetControllerID(controllerID)

	if err := m.registerController(); err != nil {
		return nil, err
	}

	m.startHeartbeat()
	m.startCleanupLoop()
	m.startPropagation()

	managerMu.Lock()
	manager = m
	managerMu.Unlock()

	common.Info(nil, `CLUSTER_INIT`, `success`, ``, map[string]any{
		`controller_id`: controllerID,
		`public_url`:    m.publicURL,
		`lease_ttl_s`:   int(cfg.LeaseTTL.Seconds()),
	})

	return m, nil
}

// Current returns the active manager (can be nil if clustering is disabled).
func Current() *Manager {
	managerMu.RLock()
	defer managerMu.RUnlock()
	return manager
}

// ControllerID returns this controller's identifier.
func (m *Manager) ControllerID() string {
	if m == nil {
		return ""
	}
	return m.controllerID
}

// Stop shuts down background goroutines.
func (m *Manager) Stop() {
	if m == nil {
		return
	}
	m.cancel()
	m.wg.Wait()
}

// RecordDeviceOnline claims or refreshes the device lease for this controller.
func (m *Manager) RecordDeviceOnline(ctx context.Context, device modules.Device) {
	if m == nil {
		return
	}

	owned, redirect := m.ClaimDeviceForHandshake(ctx, device)
	if redirect != `` && redirect != m.publicURL {
		m.dropDevice(device.ID, `claimed_by_other`)
		return
	}
	if !owned {
		return
	}
}

// ClaimDeviceForHandshake attempts to claim a device; when owned by another controller it returns a redirect target.
func (m *Manager) ClaimDeviceForHandshake(ctx context.Context, device modules.Device) (bool, string) {
	if m == nil {
		return false, ``
	}

	meta := map[string]any{
		`os`:       device.OS,
		`arch`:     device.Arch,
		`hostname`: device.Hostname,
		`lan`:      device.LAN,
		`wan`:      device.WAN,
		`mac`:      device.MAC,
		`user`:     device.Username,
		`caps`:     []string{`desktop`, `terminal`, `file`, `process`, `audio`, `webcam`},
	}

	staleControllers, err := m.staleControllerIDs(ctx)
	if err != nil {
		common.Warn(ctx, `DEVICE_CLAIM`, `warn`, err.Error(), map[string]any{
			`device`: device.ID,
		})
	}

	// If device is already owned by a healthy controller, redirect there.
	if devDoc, _ := storage.GetDevice(ctx, device.ID); devDoc != nil && devDoc.ControllerID != `` && devDoc.ControllerID != m.controllerID && !contains(staleControllers, devDoc.ControllerID) {
		if target := m.controllerURL(ctx, devDoc.ControllerID); target != `` {
			return false, target
		}
	}

	// Choose best controller (least device count) among healthy controllers.
	targetController, targetURL := m.pickController(ctx, staleControllers)
	if targetController == `` {
		targetController = m.controllerID
	}

	// If best controller is not us, redirect.
	if targetController != m.controllerID {
		if targetURL != `` {
			return false, targetURL
		}
	}

	doc, ok, err := storage.ClaimDevice(ctx, device.ID, m.controllerID, m.cfg.LeaseTTL, meta, ``, true, staleControllers)
	if err != nil {
		common.Warn(ctx, `DEVICE_CLAIM`, `fail`, err.Error(), map[string]any{
			`device`: device.ID,
		})
		return false, ``
	}

	controller := ``
	if doc != nil {
		controller = doc.ControllerID
	}
	if controller == `` {
		if devDoc, _ := storage.GetDevice(ctx, device.ID); devDoc != nil {
			controller = devDoc.ControllerID
		}
	}

	outcome := `claimed`
	if !ok {
		switch {
		case controller == m.controllerID:
			outcome = `refreshed`
		case controller != ``:
			outcome = `remote_controller`
		default:
			outcome = `created`
		}
	}

	redirect := ``
	if controller != `` && controller != m.controllerID {
		redirect = m.controllerURL(ctx, controller)
	}

	if controller == m.controllerID {
		m.metrics.deviceClaims.Add(1)
	}

	_ = storage.WriteAudit(ctx, storage.Audit{
		Actor:   m.controllerID,
		Action:  `device.upsert`,
		Target:  map[string]string{`type`: `device`, `id`: device.ID},
		Outcome: outcome,
		Meta: map[string]any{
			`controllerId`: controller,
			`wan`:          device.WAN,
			`hostname`:     device.Hostname,
		},
	})

	if controller != `` && controller != m.controllerID {
		return false, redirect
	}
	return true, ``
}

// RecordDeviceHeartbeat extends the lease for a known device.
func (m *Manager) RecordDeviceHeartbeat(ctx context.Context, deviceID string) {
	if m == nil {
		return
	}
	// Reuse UpsertDevice to bump lastSeen/lease without altering metadata.
	_ = storage.UpsertDevice(ctx, deviceID, m.controllerID, m.cfg.LeaseTTL, nil, ``)
}

func (m *Manager) controllerURL(ctx context.Context, controllerID string) string {
	ctrl, err := storage.GetController(ctx, controllerID)
	if err != nil || ctrl == nil {
		return ``
	}
	return extractPublicURL(ctrl.Meta)
}

// pickController selects the best controller (least device count) among healthy controllers.
// Returns controllerID and its public URL (if any).
func (m *Manager) pickController(ctx context.Context, staleIDs []string) (string, string) {
	db := storage.GetMongoDB()
	if db == nil {
		return m.controllerID, m.publicURL
	}
	now := time.Now().UTC()
	activeFilter := bson.M{
		`lastSeen`: bson.M{`$gt`: now.Add(-m.cfg.StaleAfter)},
		`status`:   bson.M{`$ne`: `stale`},
	}
	if len(staleIDs) > 0 {
		activeFilter[`_id`] = bson.M{`$nin`: staleIDs}
	}

	cur, err := db.Collection(`controllers`).Find(ctx, activeFilter)
	if err != nil {
		return m.controllerID, m.publicURL
	}
	defer cur.Close(ctx)

	controllers := make(map[string]ctrlInfo)
	for cur.Next(ctx) {
		var c storage.Controller
		if err := cur.Decode(&c); err == nil {
			controllers[c.ID] = ctrlInfo{id: c.ID, publicURL: extractPublicURL(c.Meta)}
		}
	}

	if len(controllers) == 0 {
		return m.controllerID, m.publicURL
	}

	// Aggregate device counts per controller among active controllers
	pipeline := mongo.Pipeline{
		{{Key: `$match`, Value: bson.M{
			`controllerId`: bson.M{`$in`: keys(controllers)},
		}}},
		{{Key: `$group`, Value: bson.M{
			`_id`:   `$controllerId`,
			`count`: bson.M{`$sum`: 1},
		}}},
	}
	counts := make(map[string]int32)
	countCur, err := db.Collection(`devices`).Aggregate(ctx, pipeline)
	if err == nil {
		defer countCur.Close(ctx)
		for countCur.Next(ctx) {
			var doc struct {
				ID    string `bson:"_id"`
				Count int32  `bson:"count"`
			}
			if err := countCur.Decode(&doc); err == nil {
				counts[doc.ID] = doc.Count
			}
		}
	}

	// Choose controller with minimum count (default 0)
	bestID := m.controllerID
	bestURL := m.publicURL
	bestCount := int32(1 << 30)
	for id, info := range controllers {
		c := counts[id]
		if c < bestCount || (c == bestCount && id == m.controllerID) { // prefer self on tie
			bestCount = c
			bestID = id
			bestURL = info.publicURL
		}
	}
	return bestID, bestURL
}

func keys(m map[string]ctrlInfo) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// RecordDeviceOffline releases ownership and marks the device offline.
func (m *Manager) RecordDeviceOffline(ctx context.Context, deviceID string) {
	if m == nil {
		return
	}
	_ = storage.MarkDeviceOffline(ctx, deviceID)
	_ = storage.WriteAudit(ctx, storage.Audit{
		Actor:   m.controllerID,
		Action:  `device.offline`,
		Target:  map[string]string{`type`: `device`, `id`: deviceID},
		Outcome: `offline`,
	})
}

// StartSession stores a session lease for the given session type.
func (m *Manager) StartSession(ctx context.Context, sessionID, deviceID, userID, sessionType string) {
	if m == nil {
		return
	}
	err := storage.StartSession(ctx, sessionID, deviceID, userID, sessionType, m.controllerID, m.cfg.SessionLeaseTTL)
	if err != nil {
		common.Warn(ctx, `SESSION_START`, `fail`, err.Error(), map[string]any{
			`session`: sessionID,
			`device`:  deviceID,
			`type`:    sessionType,
		})
		return
	}
	_ = storage.WriteAudit(ctx, storage.Audit{
		Actor:   m.controllerID,
		Action:  `session.start`,
		Target:  map[string]string{`type`: `session`, `id`: sessionID},
		Outcome: `ok`,
		Meta: map[string]any{
			`deviceId`: deviceID,
			`type`:     sessionType,
		},
	})
}

// HeartbeatSession extends the lease for the session.
func (m *Manager) HeartbeatSession(ctx context.Context, sessionID string) {
	if m == nil {
		return
	}
	_ = storage.HeartbeatSession(ctx, sessionID, m.cfg.SessionLeaseTTL)
}

// CloseSession marks the session as closed and writes an audit entry.
func (m *Manager) CloseSession(ctx context.Context, sessionID, reason string) {
	if m == nil {
		return
	}
	_ = storage.CloseSession(ctx, sessionID)
	_ = storage.WriteAudit(ctx, storage.Audit{
		Actor:   m.controllerID,
		Action:  `session.close`,
		Target:  map[string]string{`type`: `session`, `id`: sessionID},
		Outcome: reason,
	})
}

// RouteDecision captures routing info when a device is owned by another controller.
type RouteDecision struct {
	ControllerID string
	TargetURL    string
}

// Stats captures a snapshot of cluster health and routing metrics.
type Stats struct {
	ControllerID           string `json:"controllerId"`
	PublicURL              string `json:"publicUrl"`
	ProxyEnabled           bool   `json:"proxyEnabled"`
	UseChangeStreams       bool   `json:"useChangeStreams"`
	OwnedDevices           int64  `json:"ownedDevices"`
	OwnedSessions          int64  `json:"ownedSessions"`
	OnlineDevices          int64  `json:"onlineDevices"`
	ActiveControllers      int64  `json:"activeControllers"`
	DeviceClaims           uint64 `json:"deviceClaims"`
	Redirects              uint64 `json:"redirects"`
	Proxied                uint64 `json:"proxied"`
	Reassignments          uint64 `json:"reassignments"`
	ChangeStreamRestarts   uint64 `json:"changeStreamRestarts"`
	StaleAfterSeconds      int    `json:"staleAfterSeconds"`
	LeaseTTLSeconds        int    `json:"leaseTtlSeconds"`
	SessionLeaseSeconds    int    `json:"sessionLeaseSeconds"`
	CleanupIntervalSeconds int    `json:"cleanupIntervalSeconds"`
}

// ShouldRedirect returns a redirect decision when the device is owned by a different controller.
func (m *Manager) ShouldRedirect(ctx context.Context, deviceID string) (*RouteDecision, error) {
	if m == nil {
		return nil, nil
	}
	if m.deviceLocal(deviceID) {
		return nil, nil
	}

	device, err := storage.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, err
	}
	if device == nil || device.ControllerID == `` || device.ControllerID == m.controllerID {
		return nil, nil
	}

	ctrl, err := storage.GetController(ctx, device.ControllerID)
	if err != nil {
		return nil, err
	}
	if ctrl == nil {
		return nil, nil
	}
	publicURL := extractPublicURL(ctrl.Meta)
	if publicURL == `` {
		return nil, nil
	}

	return &RouteDecision{
		ControllerID: device.ControllerID,
		TargetURL:    publicURL,
	}, nil
}

// Stats returns a snapshot of cluster state and counters.
func (m *Manager) Stats(ctx context.Context) Stats {
	if m == nil {
		return Stats{}
	}

	stats := Stats{
		ControllerID:           m.controllerID,
		PublicURL:              m.publicURL,
		ProxyEnabled:           m.cfg.PreferProxy,
		UseChangeStreams:       m.cfg.UseChangeStreams,
		DeviceClaims:           m.metrics.deviceClaims.Load(),
		Redirects:              m.metrics.redirects.Load(),
		Proxied:                m.metrics.proxied.Load(),
		Reassignments:          m.metrics.reassignments.Load(),
		ChangeStreamRestarts:   m.metrics.changeStreamRestarts.Load(),
		StaleAfterSeconds:      int(m.cfg.StaleAfter.Seconds()),
		LeaseTTLSeconds:        int(m.cfg.LeaseTTL.Seconds()),
		SessionLeaseSeconds:    int(m.cfg.SessionLeaseTTL.Seconds()),
		CleanupIntervalSeconds: int(m.cfg.CleanupInterval.Seconds()),
	}

	if ctx == nil {
		ctx = context.Background()
	}
	dbCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	if storage.IsMongoEnabled() {
		if v, err := storage.CountDevices(dbCtx, bson.M{"controllerId": m.controllerID}); err == nil {
			stats.OwnedDevices = v
		}
		if v, err := storage.CountSessions(dbCtx, bson.M{"controllerId": m.controllerID, "state": bson.M{"$ne": "closed"}}); err == nil {
			stats.OwnedSessions = v
		}
		if v, err := storage.CountDevices(dbCtx, bson.M{"status": "online"}); err == nil {
			stats.OnlineDevices = v
		}
		if v, err := storage.CountControllers(dbCtx, bson.M{"lastSeen": bson.M{"$gt": time.Now().UTC().Add(-m.cfg.StaleAfter)}}); err == nil {
			stats.ActiveControllers = v
		}
	}
	return stats
}

// RedirectIfNeeded issues an HTTP redirect if the device is owned by another controller.
func RedirectIfNeeded(ctx *gin.Context, deviceID string) bool {
	m := Current()
	if m == nil {
		return false
	}
	decision, err := m.ShouldRedirect(ctx, deviceID)
	if err != nil || decision == nil {
		return false
	}
	ctx.Header(`X-Controller-ID`, decision.ControllerID)
	if m.cfg.PreferProxy && m.proxyRequest(ctx, deviceID, decision) {
		m.metrics.proxied.Add(1)
		return true
	}

	target := BuildRedirectURL(decision.TargetURL, ctx.Request.URL.Path, ctx.Request.URL.RawQuery)
	if target == `` {
		return false
	}

	m.metrics.redirects.Add(1)
	ctx.Redirect(http.StatusTemporaryRedirect, target)
	return true
}

// BuildRedirectURL merges a base URL with the incoming path/query.
func BuildRedirectURL(base, path, rawQuery string) string {
	if base == `` {
		return ``
	}
	u, err := url.Parse(base)
	if err != nil {
		return ``
	}
	u.Path = path
	u.RawQuery = rawQuery
	return u.String()
}

// proxyRequest forwards the request to the owning controller instead of issuing a redirect.
// This keeps the client on a single endpoint while honoring controller ownership.
func (m *Manager) proxyRequest(ctx *gin.Context, deviceID string, decision *RouteDecision) bool {
	if decision == nil || decision.TargetURL == `` {
		return false
	}
	proxy := m.getProxy(decision.TargetURL)
	if proxy == nil {
		return false
	}

	req := ctx.Request
	req.Header.Set(`X-Cluster-From`, m.controllerID)
	req.Header.Set(`X-Cluster-Device`, deviceID)
	req.Header.Set(`X-Forwarded-Host`, req.Host)
	req.Header.Set(`X-Forwarded-Proto`, schemeFromRequest(req))

	proxy.ServeHTTP(ctx.Writer, req)
	return true
}

func (m *Manager) getProxy(target string) *httputil.ReverseProxy {
	if target == `` {
		return nil
	}
	m.proxyMu.RLock()
	proxy := m.proxies[target]
	m.proxyMu.RUnlock()
	if proxy != nil {
		return proxy
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		return nil
	}

	proxy = httputil.NewSingleHostReverseProxy(targetURL)
	proxy.FlushInterval = 100 * time.Millisecond
	proxy.Transport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   m.cfg.ProxyTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: m.cfg.ProxyTimeout,
		IdleConnTimeout:     60 * time.Second,
		ForceAttemptHTTP2:   false,
	}

	origDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		origDirector(req)
		req.Host = targetURL.Host
	}
	proxy.ErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		common.Warn(req.Context(), `CLUSTER_PROXY`, `fail`, err.Error(), map[string]any{
			`target`: target,
			`path`:   req.URL.Path,
		})
		rw.WriteHeader(http.StatusBadGateway)
	}

	m.proxyMu.Lock()
	if m.proxies == nil {
		m.proxies = make(map[string]*httputil.ReverseProxy)
	}
	m.proxies[target] = proxy
	m.proxyMu.Unlock()
	return proxy
}

func schemeFromRequest(req *http.Request) string {
	if req == nil {
		return ``
	}
	if proto := req.Header.Get(`X-Forwarded-Proto`); proto != `` {
		return proto
	}
	if req.TLS != nil {
		return `https`
	}
	if req.URL != nil && req.URL.Scheme != `` {
		return req.URL.Scheme
	}
	return `http`
}

func (m *Manager) registerController() error {
	meta := map[string]any{
		`publicURL`: m.publicURL,
		`hostname`:  hostname(),
		`pid`:       os.Getpid(),
		`startedAt`: time.Now().UTC(),
	}
	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()
	return storage.UpsertController(ctx, m.controllerID, meta, 0)
}

func (m *Manager) startHeartbeat() {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
				_ = storage.TouchController(ctx, m.controllerID)
				cancel()
			}
		}
	}()
}

func (m *Manager) startCleanupLoop() {
	m.wg.Add(1)
	go func() {
		defer m.wg.Done()
		ticker := time.NewTicker(m.cfg.CleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-m.ctx.Done():
				return
			case <-ticker.C:
				m.cleanup()
			}
		}
	}()
}

func (m *Manager) startPropagation() {
	if !m.cfg.UseChangeStreams {
		return
	}
	m.wg.Add(2)
	go m.watchDevices()
	go m.watchSessions()
}

func (m *Manager) cleanup() {
	db := storage.GetMongoDB()
	if db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(m.ctx, 5*time.Second)
	defer cancel()
	now := time.Now().UTC()
	staleSince := now.Add(-m.cfg.StaleAfter)

	// Mark stale controllers
	staleIDs, err := m.staleControllerIDs(ctx)
	if err == nil && len(staleIDs) > 0 {
		_, _ = db.Collection(`controllers`).UpdateMany(ctx, bson.M{
			`_id`: bson.M{`$in`: staleIDs},
		}, bson.M{
			`$set`: bson.M{
				`status`:    `stale`,
				`updatedAt`: now,
			},
		})
	}
	// Release devices whose lease expired or belong to stale controllers
	deviceFilter := bson.M{
		`$or`: []bson.M{
			{`leaseExpiresAt`: bson.M{`$lte`: now}},
			{`lastSeen`: bson.M{`$lte`: staleSince}},
		},
	}
	if len(staleIDs) > 0 {
		deviceFilter[`$or`] = append(deviceFilter[`$or`].([]bson.M), bson.M{
			`controllerId`: bson.M{`$in`: staleIDs},
		})
	}
	_, _ = db.Collection(`devices`).UpdateMany(ctx, deviceFilter, bson.M{
		`$set`: bson.M{
			`controllerId`:   ``,
			`status`:         `offline`,
			`leaseExpiresAt`: time.Time{},
			`updatedAt`:      now,
		},
	})

	// Close expired sessions
	sessionFilter := bson.M{
		`$or`: []bson.M{
			{`leaseExpiresAt`: bson.M{`$lte`: now}},
			{`state`: `closed`},
		},
	}
	if len(staleIDs) > 0 {
		sessionFilter[`$or`] = append(sessionFilter[`$or`].([]bson.M), bson.M{
			`controllerId`: bson.M{`$in`: staleIDs},
		})
	}
	_, _ = db.Collection(`sessions`).UpdateMany(ctx, sessionFilter, bson.M{
		`$set`: bson.M{
			`controllerId`:   ``,
			`state`:          `closed`,
			`leaseExpiresAt`: time.Time{},
			`updatedAt`:      now,
		},
	})

	claimed := m.rebalance(ctx, now, staleIDs)
	if claimed > 0 {
		common.Info(nil, `CLUSTER_REBALANCE`, `claimed`, ``, map[string]any{
			`claimed`:     claimed,
			`controller`:  m.controllerID,
			`stale_count`: len(staleIDs),
		})
	}
}

// rebalance attempts to claim a limited set of orphaned or stale devices.
func (m *Manager) rebalance(ctx context.Context, now time.Time, staleIDs []string) int {
	db := storage.GetMongoDB()
	if db == nil {
		return 0
	}

	filter := bson.M{
		`$or`: []bson.M{
			{`controllerId`: bson.M{`$exists`: false}},
			{`controllerId`: ``},
			{`leaseExpiresAt`: bson.M{`$lte`: now}},
		},
	}
	if len(staleIDs) > 0 {
		filter[`$or`] = append(filter[`$or`].([]bson.M), bson.M{
			`controllerId`: bson.M{`$in`: staleIDs},
		})
	}

	cur, err := db.Collection(`devices`).Find(ctx, filter, options.Find().
		SetProjection(bson.M{`_id`: 1, `meta`: 1}).
		SetLimit(20))
	if err != nil {
		return 0
	}
	defer cur.Close(ctx)

	claimed := 0
	for cur.Next(ctx) {
		var doc struct {
			ID   string         `bson:"_id"`
			Meta map[string]any `bson:"meta"`
		}
		if err := cur.Decode(&doc); err != nil || doc.ID == `` {
			continue
		}
		if _, ok, err := storage.ClaimDevice(ctx, doc.ID, m.controllerID, m.cfg.LeaseTTL, doc.Meta, ``, true, staleIDs); err == nil && ok {
			claimed++
			m.metrics.reassignments.Add(1)
		}
	}
	return claimed
}

func (m *Manager) watchDevices() {
	defer m.wg.Done()
	backoff := newRetryBackoff(time.Second, 30*time.Second)
	for {
		if m.ctx.Err() != nil {
			return
		}
		if err := m.consumeDeviceStream(); err != nil {
			if !changeStreamsSupported(err) {
				common.Warn(nil, `DEVICE_WATCH`, `disabled`, err.Error(), nil)
				return
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			delay := backoff.Next()
			m.metrics.changeStreamRestarts.Add(1)
			common.Warn(nil, `DEVICE_WATCH`, `retry`, fmt.Sprintf("change stream error: %v (retry in %s)", err, delay), nil)
			select {
			case <-time.After(delay):
			case <-m.ctx.Done():
				return
			}
			continue
		}
		backoff.Reset()
		return
	}
}

func (m *Manager) consumeDeviceStream() error {
	coll := storage.GetCollection(`devices`)
	if coll == nil {
		return fmt.Errorf("devices collection unavailable")
	}
	opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
	cs, err := coll.Watch(m.ctx, mongo.Pipeline{}, opts)
	if err != nil {
		return err
	}
	defer cs.Close(m.ctx)

	for cs.Next(m.ctx) {
		var event struct {
			OperationType string         `bson:"operationType"`
			FullDocument  storage.Device `bson:"fullDocument"`
			DocumentKey   map[string]any `bson:"documentKey"`
			UpdateDesc    map[string]any `bson:"updateDescription"`
		}
		if err := cs.Decode(&event); err != nil {
			continue
		}
		switch event.OperationType {
		case `delete`:
			if id, ok := event.DocumentKey[`_id`].(string); ok {
				m.dropDevice(id, `deleted`)
			}
		case `replace`, `update`, `insert`:
			doc := event.FullDocument
			if doc.ControllerID != `` && doc.ControllerID != m.controllerID {
				m.dropDevice(doc.ID, `moved`)
			}
		}
	}
	if err := cs.Err(); err != nil {
		return err
	}
	if err := m.ctx.Err(); err != nil {
		return err
	}
	return fmt.Errorf("device change stream closed")
}

func (m *Manager) watchSessions() {
	defer m.wg.Done()
	backoff := newRetryBackoff(time.Second, 30*time.Second)
	for {
		if m.ctx.Err() != nil {
			return
		}
		if err := m.consumeSessionStream(); err != nil {
			if !changeStreamsSupported(err) {
				common.Warn(nil, `SESSION_WATCH`, `disabled`, err.Error(), nil)
				return
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			delay := backoff.Next()
			m.metrics.changeStreamRestarts.Add(1)
			common.Warn(nil, `SESSION_WATCH`, `retry`, fmt.Sprintf("change stream error: %v (retry in %s)", err, delay), nil)
			select {
			case <-time.After(delay):
			case <-m.ctx.Done():
				return
			}
			continue
		}
		backoff.Reset()
		return
	}
}

func (m *Manager) consumeSessionStream() error {
	coll := storage.GetCollection(`sessions`)
	if coll == nil {
		return fmt.Errorf("sessions collection unavailable")
	}
	opts := options.ChangeStream().SetFullDocument(options.UpdateLookup)
	cs, err := coll.Watch(m.ctx, mongo.Pipeline{}, opts)
	if err != nil {
		return err
	}
	defer cs.Close(m.ctx)

	for cs.Next(m.ctx) {
		var event struct {
			OperationType string          `bson:"operationType"`
			FullDocument  storage.Session `bson:"fullDocument"`
			DocumentKey   map[string]any  `bson:"documentKey"`
		}
		if err := cs.Decode(&event); err != nil {
			continue
		}
		doc := event.FullDocument
		if doc.ControllerID != `` && doc.ControllerID != m.controllerID {
			m.dropDevice(doc.DeviceID, `session_moved`)
			continue
		}
		if doc.State == `closed` || (!doc.LeaseExpires.IsZero() && doc.LeaseExpires.Before(time.Now().UTC())) {
			m.dropDevice(doc.DeviceID, `session_closed`)
		}
	}
	if err := cs.Err(); err != nil {
		return err
	}
	if err := m.ctx.Err(); err != nil {
		return err
	}
	return fmt.Errorf("session change stream closed")
}

func (m *Manager) deviceLocal(deviceID string) bool {
	found := false
	common.Devices.IterCb(func(_ string, d *modules.Device) bool {
		if d.ID == deviceID {
			found = true
			return false
		}
		return true
	})
	return found
}

func (m *Manager) dropDevice(deviceID, reason string) {
	var targetUUID string
	common.Devices.IterCb(func(uuid string, d *modules.Device) bool {
		if d.ID == deviceID {
			targetUUID = uuid
			return false
		}
		return true
	})
	if targetUUID == `` {
		return
	}
	if session, ok := common.Melody.GetSessionByUUID(targetUUID); ok {
		common.Warn(nil, `DEVICE_DROP`, ``, reason, map[string]any{
			`device`: deviceID,
		})
		session.Close()
	}
	common.Devices.Remove(targetUUID)
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

func (m *Manager) staleControllerIDs(ctx context.Context) ([]string, error) {
	db := storage.GetMongoDB()
	if db == nil {
		return nil, nil
	}
	cur, err := db.Collection(`controllers`).Find(ctx, bson.M{
		`_id`:      bson.M{`$ne`: m.controllerID},
		`lastSeen`: bson.M{`$lte`: time.Now().UTC().Add(-m.cfg.StaleAfter)},
	})
	if err != nil {
		return nil, err
	}
	defer cur.Close(ctx)
	var ids []string
	for cur.Next(ctx) {
		var doc storage.Controller
		if err := cur.Decode(&doc); err == nil {
			ids = append(ids, doc.ID)
		}
	}
	return ids, nil
}

type retryBackoff struct {
	current time.Duration
	initial time.Duration
	max     time.Duration
}

func newRetryBackoff(initial, max time.Duration) *retryBackoff {
	return &retryBackoff{
		initial: initial,
		max:     max,
	}
}

func (b *retryBackoff) Next() time.Duration {
	if b.current == 0 {
		b.current = b.initial
	} else {
		b.current *= 2
		if b.current > b.max {
			b.current = b.max
		}
	}
	return b.current
}

func (b *retryBackoff) Reset() {
	b.current = 0
}

func changeStreamsSupported(err error) bool {
	if err == nil {
		return true
	}
	msg := err.Error()
	return !(strings.Contains(msg, "not supported") ||
		strings.Contains(msg, "ChangeStreamNotSupported") ||
		strings.Contains(msg, "replica set") ||
		strings.Contains(msg, "not primary"))
}

func applyDefaults(cfg Config) Config {
	if cfg.LeaseTTL == 0 {
		cfg.LeaseTTL = 2 * time.Minute
	}
	if cfg.SessionLeaseTTL == 0 {
		cfg.SessionLeaseTTL = 3 * time.Minute
	}
	if cfg.StaleAfter == 0 {
		cfg.StaleAfter = 90 * time.Second
	}
	if cfg.CleanupInterval == 0 {
		cfg.CleanupInterval = 30 * time.Second
	}
	if cfg.ProxyTimeout == 0 {
		cfg.ProxyTimeout = 10 * time.Second
	}
	return cfg
}

func resolveControllerID(path, fallback string) (string, error) {
	if path != `` {
		data, err := os.ReadFile(path)
		if err == nil {
			if v := strings.TrimSpace(string(data)); v != `` {
				return v, nil
			}
		}
		if err != nil && !os.IsNotExist(err) {
			return ``, fmt.Errorf(`read controller id file: %w`, err)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return ``, fmt.Errorf(`create controller id dir: %w`, err)
		}
		if fallback == `` {
			fallback = utils.GetStrUUID()
		}
		if err := os.WriteFile(path, []byte(fallback), 0o600); err != nil {
			return ``, fmt.Errorf(`write controller id file: %w`, err)
		}
		return fallback, nil
	}
	if fallback != `` {
		return fallback, nil
	}
	return utils.GetStrUUID(), nil
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return `unknown`
	}
	return h
}

func extractPublicURL(meta any) string {
	if meta == nil {
		return ``
	}
	m, ok := meta.(map[string]any)
	if !ok {
		return ``
	}
	if v, ok := m[`publicURL`].(string); ok {
		return v
	}
	if v, ok := m[`public_url`].(string); ok {
		return v
	}
	return ``
}
