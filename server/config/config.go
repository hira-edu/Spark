package config

import (
	"Rocket/utils"
	"bytes"
	"flag"
	"github.com/kataras/golog"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
)

type config struct {
	Listen    string            `json:"listen"`
	Salt      string            `json:"salt"`
	Auth      map[string]string `json:"auth"`
	Log       *log              `json:"log"`
	TLS       *tls              `json:"tls"`
	WebRTC    *webrtc           `json:"webrtc"`
	Transport *transport        `json:"transport"` // Transport configuration
	P2P       *p2p              `json:"p2p"`       // P2P defaults for generated clients
	MongoDB   *mongodb          `json:"mongodb"`   // MongoDB configuration
	Cluster   *cluster          `json:"cluster"`   // Cluster/broker configuration
	Desktop   *desktop          `json:"desktop"`   // Remote desktop defaults
	SaltBytes []byte            `json:"-"`
}

type tls struct {
	Enable   bool      `json:"enable"`
	CertFile string    `json:"cert"`
	KeyFile  string    `json:"key"`
	AutoCert *autoCert `json:"autocert"`
}

type autoCert struct {
	Enable   bool     `json:"enable"`
	Domains  []string `json:"domains"`
	Email    string   `json:"email"`
	CacheDir string   `json:"cache_dir"`
}
type log struct {
	Level string `json:"level"`
	Path  string `json:"path"`
	Days  uint   `json:"days"`
}

type webrtc struct {
	Turn []string `json:"turn_servers"`
	Stun []string `json:"stun_servers"`

	// TurnSecret is the shared secret for RFC 8656 ephemeral credentials (coturn --use-auth-secret)
	// If set, time-limited credentials are generated for each ICE config request.
	// If empty, TURN URIs are returned without credentials (static auth mode).
	TurnSecret string `json:"turn_secret"`

	// TurnCredentialTTL is the validity period in seconds for ephemeral credentials (default: 3600)
	TurnCredentialTTL int `json:"turn_credential_ttl"`
}

type transport struct {
	// Long Polling configuration
	LongPolling *longPolling `json:"long_polling"`

	// QUIC configuration
	QUIC *quic `json:"quic"`

	// DNS Tunneling configuration
	DNS *dnsConfig `json:"dns"`
}

type p2p struct {
	Enable        bool     `json:"enable"`
	RendezvousURL string   `json:"rendezvous_url"`
	Target        string   `json:"target"`
	STUNServers   []string `json:"stun_servers"`
}

type longPolling struct {
	Enable bool `json:"enable"` // Enable long polling transport
}

type quic struct {
	Enable bool   `json:"enable"` // Enable QUIC transport
	Listen string `json:"listen"` // QUIC listen address (e.g., ":443")
}

type dnsConfig struct {
	Enable bool   `json:"enable"` // Enable DNS tunneling
	Listen string `json:"listen"` // DNS listen address (e.g., ":53")
	Domain string `json:"domain"` // Domain for DNS tunneling (e.g., "c2.example.com")
}

type mongodb struct {
	Enable   bool   `json:"enable"`   // Enable MongoDB for persistent storage
	URI      string `json:"uri"`      // MongoDB connection URI
	Database string `json:"database"` // Database name
}

type cluster struct {
	Enable                 bool   `json:"enable"`                   // Enable clustered/brokered mode
	ControllerID           string `json:"controller_id"`            // Optional static controller ID
	PublicURL              string `json:"public_url"`               // External URL for this controller (used for redirects)
	ControllerIDFile       string `json:"controller_id_file"`       // Where to persist controller ID
	LeaseTTLSeconds        int    `json:"lease_ttl_seconds"`        // Lease duration for device ownership
	SessionLeaseSeconds    int    `json:"session_lease_seconds"`    // Lease duration for user sessions
	StaleAfterSeconds      int    `json:"stale_after_seconds"`      // Consider controller stale after this many seconds without heartbeat
	CleanupIntervalSeconds int    `json:"cleanup_interval_seconds"` // How often to run cleanup/rebalance
	UseChangeStreams       *bool  `json:"use_change_streams"`       // Prefer MongoDB change streams for propagation
	PreferProxy            *bool  `json:"prefer_proxy"`             // Prefer proxying over redirects for remote controllers
	ProxyTimeoutSeconds    int    `json:"proxy_timeout_seconds"`    // Dial/TLS timeout for proxy handoff
}

type desktop struct {
	Capture captureConfig `json:"capture"`
}

type captureConfig struct {
	Mode          string   `json:"mode"`
	EnablePreDWM  bool     `json:"enable_pre_dwm"`
	FallbackOrder []string `json:"fallback_order"`
	AdapterLUID   string   `json:"adapter_luid"`
}

// Commit is hash of this commit, for auto upgrade.
var Commit = ``
var Config config
var BuiltPath = `./built/%v_%v`

func buildRevision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok || info == nil {
		return ``
	}
	for _, setting := range info.Settings {
		if setting.Key == `vcs.revision` && len(setting.Value) > 0 {
			return setting.Value
		}
	}
	return ``
}

func runningUnderTests() bool {
	exe := filepath.Base(os.Args[0])
	return strings.HasSuffix(exe, ".test")
}

func init() {
	if runningUnderTests() {
		Config = config{
			Log: &log{
				Level: "disable",
				Path:  "./logs",
				Days:  7,
			},
		}
		return
	}

	golog.SetTimeFormat(`2006/01/02 15:04:05`)

	var (
		err                      error
		configData               []byte
		configPath, listen, salt string
		username, password       string
		logLevel, logPath        string
		logDays                  uint
		tlsEnable                bool
		tlsCert, tlsKey          string
		tlsAutoCert              bool
		tlsDomains               string
		tlsEmail                 string
		tlsCacheDir              string
	)
	flag.StringVar(&configPath, `config`, `config.json`, `config file path, default: config.json`)
	flag.StringVar(&listen, `listen`, `:8000`, `required, listen address, default: :8000`)
	flag.StringVar(&salt, `salt`, ``, `required, salt of server`)
	flag.StringVar(&username, `username`, ``, `username of web interface`)
	flag.StringVar(&password, `password`, ``, `password of web interface`)
	flag.StringVar(&logLevel, `log-level`, `info`, `log level, default: info`)
	flag.StringVar(&logPath, `log-path`, `./logs`, `log file path, default: ./logs`)
	flag.UintVar(&logDays, `log-days`, 7, `max days of logs, default: 7`)
	flag.BoolVar(&tlsEnable, `tls`, false, `enable TLS/HTTPS`)
	flag.StringVar(&tlsCert, `tls-cert`, ``, `path to TLS certificate file`)
	flag.StringVar(&tlsKey, `tls-key`, ``, `path to TLS private key file`)
	flag.BoolVar(&tlsAutoCert, `tls-autocert`, false, `enable automatic Let's Encrypt certificates`)
	flag.StringVar(&tlsDomains, `tls-domains`, ``, `comma-separated list of domains for autocert`)
	flag.StringVar(&tlsEmail, `tls-email`, ``, `email for Let's Encrypt notifications`)
	flag.StringVar(&tlsCacheDir, `tls-cache`, `./certs`, `directory to cache Let's Encrypt certificates`)
	flag.Parse()

	if len(configPath) > 0 {
		configData, err = os.ReadFile(configPath)
		if err != nil {
			configData, err = os.ReadFile(`Config.json`)
			if err != nil {
				fatal(map[string]any{
					`event`:  `CONFIG_LOAD`,
					`status`: `fail`,
					`msg`:    err.Error(),
				})
				return
			}
		}
		err = utils.JSON.Unmarshal(configData, &Config)
		if err != nil {
			fatal(map[string]any{
				`event`:  `CONFIG_PARSE`,
				`status`: `fail`,
				`msg`:    err.Error(),
			})
			return
		}
		if Config.Log == nil {
			Config.Log = &log{
				Level: `info`,
				Path:  `./logs`,
				Days:  7,
			}
		}
	} else {
		Config = config{
			Listen: listen,
			Salt:   salt,
			Auth: map[string]string{
				username: password,
			},
			Log: &log{
				Level: logLevel,
				Path:  logPath,
				Days:  logDays,
			},
		}
		if tlsEnable || tlsAutoCert {
			Config.TLS = &tls{
				Enable:   tlsEnable,
				CertFile: tlsCert,
				KeyFile:  tlsKey,
			}
			if tlsAutoCert {
				domains := []string{}
				if len(tlsDomains) > 0 {
					for _, d := range bytes.Split([]byte(tlsDomains), []byte(`,`)) {
						domains = append(domains, string(bytes.TrimSpace(d)))
					}
				}
				Config.TLS.AutoCert = &autoCert{
					Enable:   true,
					Domains:  domains,
					Email:    tlsEmail,
					CacheDir: tlsCacheDir,
				}
			}
		}
	}

	if len(Config.Salt) > 24 {
		fatal(map[string]any{
			`event`:  `CONFIG_PARSE`,
			`status`: `fail`,
			`msg`:    `length of salt should less than 24`,
		})
		return
	}
	Config.SaltBytes = []byte(Config.Salt)
	Config.SaltBytes = append(Config.SaltBytes, bytes.Repeat([]byte{25}, 24)...)
	Config.SaltBytes = Config.SaltBytes[:24]

	if len(Commit) == 0 {
		if rev := buildRevision(); len(rev) > 0 {
			Commit = rev
		} else {
			Commit = `dev`
			golog.Warn(`Commit hash not set at build time; using fallback 'dev'`)
		}
	}

	// Initialize transport defaults if not configured
	if Config.Transport == nil {
		Config.Transport = &transport{}
	}
	if Config.Transport.LongPolling == nil {
		Config.Transport.LongPolling = &longPolling{Enable: true} // Default: enabled
	}
	if Config.Transport.QUIC == nil {
		Config.Transport.QUIC = &quic{
			Enable: true,
			Listen: Config.Listen, // Use same port as main server
		}
	}
	if Config.Transport.DNS == nil {
		Config.Transport.DNS = &dnsConfig{
			Enable: false, // Default: disabled (requires DNS domain setup)
			Listen: ":53",
			Domain: "", // Must be configured by operator
		}
	}

	// Initialize cluster defaults
	if Config.Cluster == nil {
		Config.Cluster = &cluster{}
	}
	if Config.MongoDB != nil && Config.MongoDB.Enable && !Config.Cluster.Enable {
		Config.Cluster.Enable = true
	}
	if Config.Cluster.ControllerIDFile == "" {
		Config.Cluster.ControllerIDFile = "./data/controller.id"
	}
	if Config.Cluster.LeaseTTLSeconds == 0 {
		Config.Cluster.LeaseTTLSeconds = 120
	}
	if Config.Cluster.SessionLeaseSeconds == 0 {
		Config.Cluster.SessionLeaseSeconds = 180
	}
	if Config.Cluster.StaleAfterSeconds == 0 {
		Config.Cluster.StaleAfterSeconds = 90
	}
	if Config.Cluster.CleanupIntervalSeconds == 0 {
		Config.Cluster.CleanupIntervalSeconds = 30
	}
	if Config.Cluster.UseChangeStreams == nil {
		v := true
		Config.Cluster.UseChangeStreams = &v
	}
	if Config.Cluster.PreferProxy == nil {
		v := true
		Config.Cluster.PreferProxy = &v
	}
	if Config.Cluster.ProxyTimeoutSeconds == 0 {
		Config.Cluster.ProxyTimeoutSeconds = 10
	}

	// Initialize WebRTC defaults if not configured
	if Config.WebRTC == nil {
		Config.WebRTC = &webrtc{}
	}
	// Provide default STUN servers if none configured
	if len(Config.WebRTC.Stun) == 0 {
		Config.WebRTC.Stun = []string{
			"stun:stun.l.google.com:19302",
			"stun:stun.cloudflare.com:3478",
		}
	}
	// Default credential TTL for TURN ephemeral auth
	if Config.WebRTC.TurnCredentialTTL == 0 {
		Config.WebRTC.TurnCredentialTTL = 3600
	}

	golog.SetLevel(utils.If(len(Config.Log.Level) == 0, `info`, Config.Log.Level))
}

func fatal(args map[string]any) {
	output, _ := utils.JSON.MarshalToString(args)
	golog.Fatal(output)
}
