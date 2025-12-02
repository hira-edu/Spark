package main

import (
	"Rocket/modules"
	"Rocket/server/cluster"
	"Rocket/server/common"
	"Rocket/server/config"
	"Rocket/server/handler"
	"Rocket/server/handler/audio"
	authHandler "Rocket/server/handler/auth"
	"Rocket/server/handler/desktop"
	dnshandler "Rocket/server/handler/dns"
	quichandler "Rocket/server/handler/quic"
	"Rocket/server/handler/share"
	"Rocket/server/handler/terminal"
	"Rocket/server/handler/utility"
	"Rocket/server/observability"
	"Rocket/server/storage"
	"Rocket/utils/cmap"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"github.com/gofrs/flock"
	"github.com/rakyll/statik/fs"
	"golang.org/x/crypto/acme/autocert"
	"io"
	"net"
	"os"
	"os/signal"
	"path"
	"strings"
	"syscall"
	"time"

	_ "Rocket/server/embed/web"
	"Rocket/utils"
	"Rocket/utils/melody"
	"net/http"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const serverLockPath = "/tmp/rocket-server.lock"

var blocked = cmap.New[int64]()
var lastRequest = time.Now().Unix()
var wsTracer = otel.Tracer("rocket-server/ws")

func main() {
	otelShutdown, err := observability.Init(context.Background())
	if err != nil {
		common.Warn(nil, `OTEL_INIT`, `fail`, err.Error(), nil)
	}
	defer otelShutdown(context.Background())

	lock := flock.New(serverLockPath)
	locked, err := lock.TryLock()
	if err != nil {
		common.Fatal(nil, `INSTANCE_LOCK`, `fail`, err.Error(), map[string]any{
			`path`: serverLockPath,
		})
		return
	}
	if !locked {
		common.Fatal(nil, `INSTANCE_LOCK`, `fail`, `another rocket-server instance is already running`, map[string]any{
			`path`: serverLockPath,
		})
		return
	}
	defer lock.Unlock()
	common.Info(nil, `INSTANCE_LOCK`, `acquired`, ``, map[string]any{
		`path`: serverLockPath,
	})

	var clusterMgr *cluster.Manager
	if common.GetControllerID() == "" {
		common.SetControllerID(utils.GetStrUUID())
	}

	// Initialize MongoDB if enabled
	if config.Config.MongoDB != nil && config.Config.MongoDB.Enable {
		if err := storage.InitMongoDB(config.Config.MongoDB.URI, config.Config.MongoDB.Database); err != nil {
			common.Fatal(nil, `MONGODB_INIT`, `fail`, err.Error(), nil)
			return
		}
		common.Info(nil, `MONGODB_INIT`, `success`, ``, map[string]any{
			`database`: config.Config.MongoDB.Database,
		})

		// Initialize auth module after MongoDB is ready
		authHandler.Init()
	} else {
		common.Warn(nil, `MONGODB_INIT`, `disabled`, `Share persistence will not be available`, nil)
	}

	if config.Config.Cluster != nil && config.Config.Cluster.Enable && storage.IsMongoEnabled() {
		useStreams := true
		if config.Config.Cluster.UseChangeStreams != nil {
			useStreams = *config.Config.Cluster.UseChangeStreams
		}
		preferProxy := true
		if config.Config.Cluster.PreferProxy != nil {
			preferProxy = *config.Config.Cluster.PreferProxy
		}
		proxyTimeout := time.Duration(config.Config.Cluster.ProxyTimeoutSeconds) * time.Second
		if proxyTimeout == 0 {
			proxyTimeout = 10 * time.Second
		}

		clusterCfg := cluster.Config{
			Enable:           true,
			ControllerID:     config.Config.Cluster.ControllerID,
			ControllerIDFile: config.Config.Cluster.ControllerIDFile,
			PublicURL:        config.Config.Cluster.PublicURL,
			LeaseTTL:         time.Duration(config.Config.Cluster.LeaseTTLSeconds) * time.Second,
			SessionLeaseTTL:  time.Duration(config.Config.Cluster.SessionLeaseSeconds) * time.Second,
			StaleAfter:       time.Duration(config.Config.Cluster.StaleAfterSeconds) * time.Second,
			CleanupInterval:  time.Duration(config.Config.Cluster.CleanupIntervalSeconds) * time.Second,
			UseChangeStreams: useStreams,
			PreferProxy:      preferProxy,
			ProxyTimeout:     proxyTimeout,
		}

		clusterMgr, err = cluster.Init(clusterCfg)
		if err != nil {
			common.Fatal(nil, `CLUSTER_INIT`, `fail`, err.Error(), nil)
			return
		}
	} else if common.GetControllerID() == "" {
		common.SetControllerID(utils.GetStrUUID())
	}

	webFS, err := fs.NewWithNamespace(`web`)
	if err != nil {
		common.Fatal(nil, `LOAD_STATIC_RES`, `fail`, err.Error(), nil)
		return
	}
	gin.SetMode(gin.ReleaseMode)
	app := gin.New()
	app.Use(otelgin.Middleware("rocket-server"))
	app.Use(requestLogger(), gin.Recovery())
	{
		handler.AuthHandler = authHandler.CheckAuth()
		handler.InitRouter(app.Group(`/api`))

		// Initialize long polling routes if enabled
		if config.Config.Transport != nil && config.Config.Transport.LongPolling != nil && config.Config.Transport.LongPolling.Enable {
			handler.InitLongPollingRoutes(app.Group(`/api`))
			common.Info(nil, `LONGPOLL_ENABLED`, ``, ``, nil)
		}

		app.Any(`/ws`, wsHandshake)
		app.NoRoute(func(ctx *gin.Context) {
			path := ctx.Request.URL.Path
			// Let API/WebSocket return 404 as usual
			if strings.HasPrefix(path, "/api") || path == "/ws" {
				ctx.Status(http.StatusNotFound)
				return
			}

			// Serve static asset (gzip/plain) if present; otherwise return SPA shell
			if serveGzip(ctx, webFS) || serveStatic(ctx, webFS) {
				return
			}

			if ctx.Request.Method != http.MethodGet && ctx.Request.Method != http.MethodHead {
				ctx.Status(http.StatusNotFound)
				return
			}

			serveIndex(ctx, webFS)
		})
	}

	common.Melody.Config.MaxMessageSize = common.MaxMessageSize
	common.Melody.HandleConnect(wsOnConnect)
	common.Melody.HandleMessage(wsOnMessage)
	common.Melody.HandleMessageBinary(wsOnMessageBinary)
	common.Melody.HandleDisconnect(wsOnDisconnect)
	go wsHealthCheck(common.Melody)

	srv := &http.Server{
		Addr:    config.Config.Listen,
		Handler: app,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			ctx = context.WithValue(ctx, `Conn`, c)
			ctx = context.WithValue(ctx, `ClientIP`, common.GetAddrIP(c.RemoteAddr()))
			return ctx
		},
	}

	// Configure TLS if enabled
	tlsEnabled := false
	tlsInfo := map[string]any{`listen`: config.Config.Listen}
	if config.Config.TLS != nil && (config.Config.TLS.Enable || (config.Config.TLS.AutoCert != nil && config.Config.TLS.AutoCert.Enable)) {
		tlsEnabled = true
		tlsInfo[`tls`] = true

		if config.Config.TLS.AutoCert != nil && config.Config.TLS.AutoCert.Enable {
			// Let's Encrypt autocert
			cacheDir := config.Config.TLS.AutoCert.CacheDir
			if cacheDir == `` {
				cacheDir = `./certs`
			}
			m := &autocert.Manager{
				Cache:      autocert.DirCache(cacheDir),
				Prompt:     autocert.AcceptTOS,
				HostPolicy: autocert.HostWhitelist(config.Config.TLS.AutoCert.Domains...),
				Email:      config.Config.TLS.AutoCert.Email,
			}
			srv.TLSConfig = m.TLSConfig()
			srv.TLSConfig.MinVersion = tls.VersionTLS12
			tlsInfo[`autocert`] = true
			tlsInfo[`domains`] = config.Config.TLS.AutoCert.Domains

			// Start HTTP->HTTPS redirect server on port 80
			go func() {
				redirectSrv := &http.Server{
					Addr:    `:80`,
					Handler: m.HTTPHandler(nil),
				}
				redirectSrv.ListenAndServe()
			}()
		} else {
			// Manual cert/key files
			tlsInfo[`cert`] = config.Config.TLS.CertFile
			srv.TLSConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}
	}

	// Start QUIC server if enabled
	if config.Config.Transport != nil && config.Config.Transport.QUIC != nil && config.Config.Transport.QUIC.Enable {
		quicAddr := config.Config.Transport.QUIC.Listen
		if quicAddr == `` {
			quicAddr = `:443` // Default QUIC port
		}

		// Use the same TLS config as HTTPS
		if srv.TLSConfig != nil {
			go func() {
				if err := quichandler.StartQUICServer(quicAddr, srv.TLSConfig); err != nil {
					common.Warn(nil, `QUIC_START_FAILED`, ``, err.Error(), nil)
				}
			}()
			common.Info(nil, `QUIC_ENABLED`, ``, ``, map[string]any{
				`listen`: quicAddr,
			})
		} else {
			common.Warn(nil, `QUIC_DISABLED`, ``, `TLS must be enabled for QUIC`, nil)
		}
	}

	// Start DNS server if enabled
	if config.Config.Transport != nil && config.Config.Transport.DNS != nil && config.Config.Transport.DNS.Enable {
		dnsAddr := config.Config.Transport.DNS.Listen
		if dnsAddr == `` {
			dnsAddr = `:53` // Default DNS port
		}

		dnsDomain := config.Config.Transport.DNS.Domain
		if dnsDomain == `` {
			common.Warn(nil, `DNS_DISABLED`, ``, `DNS domain not configured`, nil)
		} else {
			go func() {
				if err := dnshandler.StartDNSServer(dnsAddr, dnsDomain); err != nil {
					common.Warn(nil, `DNS_START_FAILED`, ``, err.Error(), nil)
				}
			}()
			common.Info(nil, `DNS_ENABLED`, ``, ``, map[string]any{
				`listen`: dnsAddr,
				`domain`: dnsDomain,
			})
		}
	}

	{
		go func() {
			if tlsEnabled {
				if config.Config.TLS.AutoCert != nil && config.Config.TLS.AutoCert.Enable {
					err = srv.ListenAndServeTLS(``, ``)
				} else {
					err = srv.ListenAndServeTLS(config.Config.TLS.CertFile, config.Config.TLS.KeyFile)
				}
			} else {
				err = srv.ListenAndServe()
			}
		}()
		if err != nil {
			common.Fatal(nil, `SERVICE_INIT`, `fail`, err.Error(), nil)
		} else {
			common.Info(nil, `SERVICE_INIT`, ``, ``, tlsInfo)
		}
	}
	quit := make(chan os.Signal, 3)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	common.Warn(nil, `SERVICE_EXITING`, ``, ``, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	// Shutdown HTTP/HTTPS server
	if err := srv.Shutdown(ctx); err != nil {
		common.Warn(nil, `SERVICE_EXIT`, `error`, err.Error(), nil)
	}

	// Shutdown QUIC server if running
	if config.Config.Transport != nil && config.Config.Transport.QUIC != nil && config.Config.Transport.QUIC.Enable {
		if err := quichandler.StopQUICServer(); err != nil {
			common.Warn(nil, `QUIC_SHUTDOWN`, `error`, err.Error(), nil)
		} else {
			common.Info(nil, `QUIC_SHUTDOWN`, `success`, ``, nil)
		}
	}

	// Shutdown DNS server if running
	if config.Config.Transport != nil && config.Config.Transport.DNS != nil && config.Config.Transport.DNS.Enable {
		if err := dnshandler.StopDNSServer(); err != nil {
			common.Warn(nil, `DNS_SHUTDOWN`, `error`, err.Error(), nil)
		} else {
			common.Info(nil, `DNS_SHUTDOWN`, `success`, ``, nil)
		}
	}

	if clusterMgr != nil {
		clusterMgr.Stop()
	}

	// Shutdown MongoDB if running
	if storage.IsMongoEnabled() {
		if err := storage.CloseMongoDB(); err != nil {
			common.Warn(nil, `MONGODB_SHUTDOWN`, `error`, err.Error(), nil)
		} else {
			common.Info(nil, `MONGODB_SHUTDOWN`, `success`, ``, nil)
		}
	}

	<-ctx.Done()
	common.Warn(nil, `SERVICE_EXIT`, `success`, ``, nil)
	common.CloseLog()
}

func requestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		latency := time.Since(start)

		common.Info(c, `HTTP_REQUEST`, `done`, ``, map[string]any{
			`method`:     c.Request.Method,
			`path`:       c.Request.URL.Path,
			`query`:      c.Request.URL.RawQuery,
			`status`:     c.Writer.Status(),
			`size`:       c.Writer.Size(),
			`latency_ms`: latency.Milliseconds(),
			`ua`:         c.Request.UserAgent(),
			`origin`:     c.Request.Header.Get(`Origin`),
			`referer`:    c.Request.Referer(),
			`upgrade`:    strings.Contains(strings.ToLower(c.GetHeader(`Connection`)), `upgrade`),
			`proto`:      c.Request.Proto,
			`host`:       c.Request.Host,
		})
	}
}

func wsHandshake(ctx *gin.Context) {
	// Child span for handshake lifecycle
	hCtx, span := wsTracer.Start(ctx.Request.Context(), "ws.handshake", trace.WithSpanKind(trace.SpanKindServer))
	defer span.End()
	ctx.Request = ctx.Request.WithContext(hCtx)

	clientIP := common.GetRemoteAddr(ctx)

	if !ctx.IsWebsocket() {
		// When message is too large to transport via websocket,
		// client will try to send these data via http.
		const MaxBodySize = 2 << 18 // 524288 512KB
		if ctx.Request.ContentLength > MaxBodySize {
			common.Warn(ctx, `WS_HTTP_REQUEST`, `fail`, `body too large`, map[string]any{
				`from`: clientIP,
				`size`: ctx.Request.ContentLength,
			})
			ctx.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, modules.Packet{Code: 1})
			return
		}
		body, err := ctx.GetRawData()
		if err != nil {
			common.Warn(ctx, `WS_HTTP_REQUEST`, `fail`, `read error: `+err.Error(), map[string]any{
				`from`: clientIP,
			})
			ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: 1})
			return
		}
		session := common.CheckClientReq(ctx)
		if session == nil {
			common.Warn(ctx, `WS_HTTP_REQUEST`, `fail`, `unauthorized`, map[string]any{
				`from`: clientIP,
			})
			ctx.AbortWithStatusJSON(http.StatusUnauthorized, modules.Packet{Code: 1})
			return
		}
		wsOnMessageBinary(session, body)
		ctx.JSON(http.StatusOK, modules.Packet{Code: 0})
		return
	}

	clientUUID, _ := hex.DecodeString(ctx.GetHeader(`UUID`))
	clientKey, _ := hex.DecodeString(ctx.GetHeader(`Key`))

	// Accept both old (32-byte encrypted) and new (16-byte plaintext) key formats
	if len(clientUUID) != 16 {
		common.Warn(ctx, `WS_HANDSHAKE`, `fail`, `invalid UUID length`, map[string]any{
			`from`:    clientIP,
			`uuidLen`: len(clientUUID),
		})
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	// Verify authentication based on key format
	var authValid bool
	if len(clientKey) == 32 {
		// Old format: 32-byte encrypted key (MD5 hash + encrypted UUID)
		// Try to decrypt and compare with UUID
		decrypted, err := common.DecAES(clientKey, config.Config.SaltBytes)
		authValid = (err == nil && bytes.Equal(decrypted, clientUUID))
	} else if len(clientKey) == 16 {
		// New format: 16-byte plaintext key (just UUID, no encryption)
		authValid = bytes.Equal(clientKey, clientUUID)
	} else {
		common.Warn(ctx, `WS_HANDSHAKE`, `fail`, `invalid key length`, map[string]any{
			`from`:   clientIP,
			`keyLen`: len(clientKey),
		})
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}

	if !authValid {
		common.Warn(ctx, `WS_HANDSHAKE`, `fail`, `auth failed`, map[string]any{
			`from`:   clientIP,
			`keyLen`: len(clientKey),
			`error`:  `key mismatch`,
		})
		ctx.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	common.Info(ctx, `WS_HANDSHAKE`, `success`, ``, map[string]any{
		`from`: clientIP,
		`uuid`: hex.EncodeToString(clientUUID)[:8] + `...`,
	})
	secret := append(utils.GetUUID(), utils.GetUUID()...)
	ctx.Writer.Header().Add(`Secret`, hex.EncodeToString(secret))
	upgradeErr := common.Melody.HandleRequestWithKeys(ctx.Writer, ctx.Request, gin.H{
		`Secret`:   secret,
		`LastPack`: utils.Unix,
		`Address`:  common.GetRemoteAddr(ctx),
	})
	if upgradeErr != nil {
		common.Warn(ctx, `WS_HANDSHAKE`, `fail`, `upgrade error: `+upgradeErr.Error(), map[string]any{
			`from`: clientIP,
		})
		span.RecordError(upgradeErr)
		ctx.AbortWithStatus(http.StatusBadRequest)
		return
	}
	span.SetAttributes(
		attribute.String("ws.client_ip", clientIP),
		attribute.String("ws.uuid_prefix", hex.EncodeToString(clientUUID)[:8]),
	)
}

func wsOnConnect(session *melody.Session) {
	ctx, span := wsTracer.Start(context.Background(), "ws.connect", trace.WithAttributes(
		attribute.String("session.uuid", session.UUID),
	))
	defer span.End()
	pingDevice(session)
	_ = ctx
}

func wsOnMessage(session *melody.Session, _ []byte) {
	session.Close()
}

func wsOnMessageBinary(session *melody.Session, data []byte) {
	ctx, span := wsTracer.Start(context.Background(), "ws.message", trace.WithAttributes(
		attribute.String("session.uuid", session.UUID),
		attribute.Int("payload.len", len(data)),
	))
	defer span.End()

	var pack modules.Packet

	dataLen := len(data)

	// Any inbound bytes indicate the channel is alive.
	session.Set(`LastPack`, utils.Unix)

	// Check for binary protocol FIRST (before size check)
	// Binary frames can be 24+ bytes (header + optional payload)
	if service, op, isBinary := utils.CheckBinaryPack(data); isBinary {
		if dataLen < 24 {
			previewLen := dataLen
			if previewLen > 64 {
				previewLen = 64
			}
			addr, _ := session.Get(`Address`)
			common.Warn(nil, `WS_MESSAGE`, `fail`, `truncated binary frame`, map[string]any{
				`from`:        addr,
				`sessionUUID`: session.UUID[:8] + `...`,
				`service`:     service,
				`op`:          op,
				`dataLen`:     dataLen,
				`payloadHex`:  hex.EncodeToString(data[:previewLen]),
			})
			span.RecordError(fmt.Errorf("binary frame too short: service=%d op=%d len=%d", service, op, dataLen))
			span.SetStatus(codes.Error, "truncated binary frame")
			return
		}

		switch service {
		case 20:
			switch op {
			case 00, 01, 02, 03:
				if dataLen >= 24 {
					event := hex.EncodeToString(data[6:22])
					common.CallEvent(modules.Packet{
						Act:   `RAW_DATA_ARRIVE`,
						Event: event,
						Data: gin.H{
							`data`: utils.GetSlicePrefix(&data, dataLen),
						},
					}, session)
				}
			}
		case 21:
			switch op {
			case 00, 01:
				if dataLen >= 24 {
					event := hex.EncodeToString(data[6:22])
					common.CallEvent(modules.Packet{
						Act:   `RAW_DATA_ARRIVE`,
						Event: event,
						Data: gin.H{
							`data`: utils.GetSlicePrefix(&data, dataLen),
						},
					}, session)
				}
			}
		default:
			previewLen := dataLen
			if previewLen > 64 {
				previewLen = 64
			}
			addr, _ := session.Get(`Address`)
			common.Warn(nil, `WS_MESSAGE`, `fail`, `unknown binary service`, map[string]any{
				`from`:        addr,
				`sessionUUID`: session.UUID[:8] + `...`,
				`service`:     service,
				`op`:          op,
				`dataLen`:     dataLen,
				`payloadHex`:  hex.EncodeToString(data[:previewLen]),
			})
			span.RecordError(fmt.Errorf("unknown binary service=%d op=%d len=%d", service, op, dataLen))
			span.SetStatus(codes.Error, "unknown binary service")
			return
		}
		return
	}

	// No decryption - parse JSON directly
	if utils.JSON.Unmarshal(data, &pack) != nil {
		addr, _ := session.Get(`Address`)
		common.Warn(nil, `WS_MESSAGE`, `fail`, `parse failed`, map[string]any{
			`from`:        addr,
			`sessionUUID`: session.UUID[:8] + `...`,
			`dataLen`:     dataLen,
			`dataHex`: func() string {
				max := dataLen
				if max > 64 {
					max = 64
				}
				return hex.EncodeToString(data[:max])
			}(),
		})
		// Don't close connection on parse failures - just log and continue
		session.Set(`LastPack`, utils.Unix)
		span.RecordError(fmt.Errorf("parse failed"))
		span.SetStatus(codes.Error, "parse failed")
		return
	}
	span.SetAttributes(
		attribute.String("packet.act", pack.Act),
		attribute.String("packet.event", pack.Event),
	)

	if pack.Act == `DEVICE_UP` || pack.Act == `DEVICE_UPDATE` {
		session.Set(`LastPack`, utils.Unix)
		utility.OnDevicePack(data, session)
		return
	}

	// Handle AUDIO_DATA packets (streaming audio from client)
	if pack.Act == `AUDIO_DATA` {
		if err := audio.HandleAudioData(pack, session.UUID); err != nil {
			common.Warn(nil, "WS_AUDIO_DATA_ERROR", session.UUID, err.Error(), nil)
		}
		session.Set(`LastPack`, utils.Unix)
		return
	}
	if !common.Devices.Has(session.UUID) {
		addr, _ := session.Get(`Address`)
		common.Warn(nil, `WS_MESSAGE`, `fail`, `device not registered`, map[string]any{
			`from`:        addr,
			`sessionUUID`: session.UUID[:8] + `...`,
			`action`:      pack.Act,
		})
		session.CloseWithMsg(melody.FormatCloseMessage(1001, `invalid device id`))
		span.SetStatus(codes.Error, "device not registered")
		return
	}
	_, actSpan := wsTracer.Start(ctx, "ws.action", trace.WithAttributes(
		attribute.String("act", pack.Act),
		attribute.String("session.uuid", session.UUID),
	))
	common.CallEvent(pack, session)
	actSpan.End()
	session.Set(`LastPack`, utils.Unix)
}

func wsOnDisconnect(session *melody.Session) {
	_, span := wsTracer.Start(context.Background(), "ws.disconnect", trace.WithAttributes(
		attribute.String("session.uuid", session.UUID),
	))
	defer span.End()

	if device, ok := common.Devices.Get(session.UUID); ok {
		terminal.CloseSessionsByDevice(device.ID)
		desktop.CloseSessionsByDevice(device.ID)
		share.CloseGuestSessionsByDevice(device.ID)
		common.Info(nil, `CLIENT_OFFLINE`, ``, ``, map[string]any{
			`device`: map[string]any{
				`name`: device.Hostname,
				`ip`:   device.WAN,
			},
		})
	} else {
		common.Info(nil, `CLIENT_OFFLINE`, ``, ``, map[string]any{
			`device`: map[string]any{
				`ip`: common.GetAddrIP(session.GetWSConn().UnderlyingConn().RemoteAddr()),
			},
		})
	}
	common.Devices.Remove(session.UUID)
}

func wsHealthCheck(container *melody.Melody) {
	const MaxIdleSeconds = 150
	const MaxPingInterval = 60
	go func() {
		// Ping clients with a dynamic interval.
		// Interval will be greater than 3 seconds and less than MaxPingInterval.
		var tick int64 = 0
		var pingInterval int64 = 3
		for range time.NewTicker(3 * time.Second).C {
			tick += 3
			if tick >= utils.Unix-lastRequest {
				pingInterval = 3
			}
			if tick >= 3 && (tick >= pingInterval || tick >= MaxPingInterval) {
				pingInterval += 3
				if pingInterval > MaxPingInterval {
					pingInterval = MaxPingInterval
				}
				tick = 0
				container.IterSessions(func(uuid string, s *melody.Session) bool {
					go pingDevice(s)
					return true
				})
			}
		}
	}()
	for now := range time.NewTicker(60 * time.Second).C {
		timestamp := now.Unix()
		// Store sessions to be disconnected.
		queue := make([]*melody.Session, 0)
		container.IterSessions(func(uuid string, s *melody.Session) bool {
			val, ok := s.Get(`LastPack`)
			if !ok {
				queue = append(queue, s)
				addr, _ := s.Get(`Address`)
				common.Warn(nil, `WS_HEALTH_CHECK`, `timeout`, `no LastPack set`, map[string]any{
					`from`:        addr,
					`sessionUUID`: uuid[:8] + `...`,
				})
				return true
			}
			lastPack, ok := val.(int64)
			if !ok {
				queue = append(queue, s)
				addr, _ := s.Get(`Address`)
				common.Warn(nil, `WS_HEALTH_CHECK`, `timeout`, `invalid LastPack type`, map[string]any{
					`from`:        addr,
					`sessionUUID`: uuid[:8] + `...`,
				})
				return true
			}
			idleSeconds := timestamp - lastPack
			if idleSeconds > MaxIdleSeconds {
				queue = append(queue, s)
				addr, _ := s.Get(`Address`)
				device, _ := common.Devices.Get(uuid)
				deviceInfo := map[string]any{`uuid`: uuid[:8] + `...`}
				if device != nil {
					deviceInfo[`name`] = device.Hostname
					deviceInfo[`ip`] = device.WAN
				}
				common.Warn(nil, `WS_HEALTH_CHECK`, `timeout`, fmt.Sprintf(`idle for %d seconds`, idleSeconds), map[string]any{
					`from`:        addr,
					`device`:      deviceInfo,
					`idleSeconds`: idleSeconds,
				})
			}
			return true
		})
		for i := 0; i < len(queue); i++ {
			queue[i].Close()
		}
	}
}

func pingDevice(s *melody.Session) {
	t := time.Now().UnixMilli()
	trigger := utils.GetStrUUID()
	common.SendPack(modules.Packet{Act: `PING`, Event: trigger}, s)
	common.AddEventOnce(func(packet modules.Packet, session *melody.Session) {
		device, ok := common.Devices.Get(s.UUID)
		if ok {
			device.Latency = uint(time.Now().UnixMilli()-t) / 2
		}
	}, s.UUID, trigger, 3*time.Second)
}

func checkAuth() gin.HandlerFunc {
	// Token as key and update timestamp as value.
	// Stores authenticated tokens.
	tokens := cmap.New[int64]()
	go func() {
		for now := range time.NewTicker(60 * time.Second).C {
			var queue []string
			tokens.IterCb(func(key string, t int64) bool {
				if now.Unix()-t > 1800 {
					queue = append(queue, key)
				}
				return true
			})
			tokens.Remove(queue...)
			queue = nil

			blocked.IterCb(func(addr string, t int64) bool {
				if now.Unix() > t {
					queue = append(queue, addr)
				}
				return true
			})
			blocked.Remove(queue...)
		}
	}()

	// Old basic auth function - now replaced by MongoDB-based auth
	// Keeping for backwards compatibility if needed
	if config.Config.Auth == nil || len(config.Config.Auth) == 0 {
		return func(ctx *gin.Context) {
			lastRequest = utils.Unix
			ctx.Next()
		}
	}

	// Old basic auth is no longer used - using MongoDB auth now
	// Returning no-op function since we use authHandler.CheckAuth() middleware now
	return func(ctx *gin.Context) {
		lastRequest = utils.Unix
		ctx.Next()
	}
}

func serveGzip(ctx *gin.Context, statikFS http.FileSystem) bool {
	headers := ctx.Request.Header
	filename := path.Clean(ctx.Request.URL.Path)
	if !strings.Contains(headers.Get(`Accept-Encoding`), `gzip`) {
		return false
	}
	if strings.Contains(headers.Get(`Connection`), `Upgrade`) {
		return false
	}
	if strings.Contains(headers.Get(`Accept`), `text/event-stream`) {
		return false
	}

	file, err := statikFS.Open(filename + `.gz`)
	if err != nil {
		return false
	}
	defer file.Close()

	ctx.Header(`Vary`, `Accept-Encoding`)
	if applyCacheHeaders(ctx, filename) {
		return true
	}

	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return false
	}

	conn, ok := ctx.Request.Context().Value(`Conn`).(net.Conn)
	if !ok {
		return false
	}

	ctx.Writer.Header().Del(`Content-Length`)
	ctx.Header(`Content-Encoding`, `gzip`)
	ctx.Status(http.StatusOK)

	for {
		eof := false
		buf := make([]byte, 2<<14)
		n, err := file.Read(buf)
		if n == 0 {
			break
		}
		if err != nil {
			eof = err == io.EOF
			if !eof {
				break
			}
		}
		conn.SetWriteDeadline(utils.Now.Add(10 * time.Second))
		_, err = ctx.Writer.Write(buf[:n])
		if eof || err != nil {
			break
		}
	}
	conn.SetWriteDeadline(time.Time{})
	ctx.Done()
	return true
}

func serveStatic(ctx *gin.Context, statikFS http.FileSystem) bool {
	if ctx.Request.Method != http.MethodGet && ctx.Request.Method != http.MethodHead {
		return false
	}

	filename := path.Clean(ctx.Request.URL.Path)
	file, err := statikFS.Open(filename)
	if err != nil {
		return false
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil || info.IsDir() {
		return false
	}

	if applyCacheHeaders(ctx, filename) {
		return true
	}

	http.ServeContent(ctx.Writer, ctx.Request, filename, info.ModTime(), file)
	return true
}

func serveIndex(ctx *gin.Context, statikFS http.FileSystem) {
	f, err := statikFS.Open("/index.html")
	if err != nil {
		http.FileServer(statikFS).ServeHTTP(ctx.Writer, ctx.Request)
		return
	}
	defer f.Close()

	ctx.Header("Content-Type", "text/html; charset=utf-8")
	ctx.Header("Cache-Control", "no-cache")
	ctx.Header("Pragma", "no-cache")
	ctx.Header("Expires", "0")
	ctx.Status(http.StatusOK)

	if ctx.Request.Method == http.MethodHead {
		return
	}

	io.Copy(ctx.Writer, f)
}

func applyCacheHeaders(ctx *gin.Context, filename string) bool {
	etag := fmt.Sprintf(`"%x-%s"`, []byte(filename), config.Commit)
	if ctx.Request.Header.Get(`If-None-Match`) == etag {
		ctx.Status(http.StatusNotModified)
		return true
	}
	ctx.Header(`ETag`, etag)
	ctx.Header(`Cache-Control`, `max-age=604800`)
	ctx.Header(`Expires`, utils.Now.Add(7*24*time.Hour).Format(`Mon, 02 Jan 2006 15:04:05 GMT`))
	return false
}
