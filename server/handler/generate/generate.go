package generate

import (
	clientcfg "Spark/client/config"
	"Spark/modules"
	"Spark/server/common"
	servercfg "Spark/server/config"
	"Spark/utils"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type clientCfg struct {
	Secure bool   `json:"secure"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Path   string `json:"path"`
	UUID   string `json:"uuid"`
	Key    string `json:"key"`

	// Transport fallback configuration
	EnableQUIC     bool   `json:"enable_quic"`      // Enable QUIC transport
	QUICPort       int    `json:"quic_port"`        // QUIC port (default: host port)
	EnableLongPoll bool   `json:"enable_longpoll"`  // Enable long polling
	EnableDNS      bool   `json:"enable_dns"`       // Enable DNS tunneling
	DNSDomain      string `json:"dns_domain"`       // DNS domain for tunneling
	DNSServer      string `json:"dns_server"`       // DNS server address
	EnableMimicry  bool   `json:"enable_mimicry"`   // Enable protocol mimicry
}

var (
	ErrTooLargeEntity = errors.New(`length of data can not excess buffer size`)
)

func CheckClient(ctx *gin.Context) {
	var form struct {
		OS     string `json:"os" yaml:"os" form:"os" binding:"required"`
		Arch   string `json:"arch" yaml:"arch" form:"arch" binding:"required"`
		Host   string `json:"host" yaml:"host" form:"host" binding:"required"`
		Port   uint16 `json:"port" yaml:"port" form:"port" binding:"required"`
		Path   string `json:"path" yaml:"path" form:"path" binding:"required"`
		Secure string `json:"secure" yaml:"secure" form:"secure"`

		// Transport fallback options
		EnableQUIC     string `json:"enable_quic" yaml:"enable_quic" form:"enable_quic"`
		QUICPort       uint16 `json:"quic_port" yaml:"quic_port" form:"quic_port"`
		EnableLongPoll string `json:"enable_longpoll" yaml:"enable_longpoll" form:"enable_longpoll"`
		EnableDNS      string `json:"enable_dns" yaml:"enable_dns" form:"enable_dns"`
		DNSDomain      string `json:"dns_domain" yaml:"dns_domain" form:"dns_domain"`
		DNSServer      string `json:"dns_server" yaml:"dns_server" form:"dns_server"`
		EnableMimicry  string `json:"enable_mimicry" yaml:"enable_mimicry" form:"enable_mimicry"`
	}
	if err := ctx.ShouldBind(&form); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	_, err := os.Stat(fmt.Sprintf(servercfg.BuiltPath, form.OS, form.Arch))
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, modules.Packet{Code: 1, Msg: `${i18n|GENERATOR.NO_PREBUILT_FOUND}`})
		return
	}
	// Use server config defaults when form doesn't specify transport settings
	enableQUIC := servercfg.Config.Transport.QUIC.Enable
	if form.EnableQUIC != "" {
		enableQUIC = form.EnableQUIC == `true`
	}

	enableLongPoll := servercfg.Config.Transport.LongPolling.Enable
	if form.EnableLongPoll != "" {
		enableLongPoll = form.EnableLongPoll == `true`
	}

	enableDNS := servercfg.Config.Transport.DNS.Enable
	if form.EnableDNS != "" {
		enableDNS = form.EnableDNS == `true`
	}

	// Use default QUIC port if not specified (defaults to main port)
	quicPort := int(form.Port)
	if form.QUICPort > 0 {
		quicPort = int(form.QUICPort)
	}

	// DNS domain from server config or form
	dnsDomain := servercfg.Config.Transport.DNS.Domain
	if form.DNSDomain != "" {
		dnsDomain = form.DNSDomain
	}

	// DNS server defaults to 8.8.8.8:53 if not specified
	dnsServer := "8.8.8.8:53"
	if form.DNSServer != "" {
		dnsServer = form.DNSServer
	}

	// Mimicry defaults to false
	enableMimicry := false
	if form.EnableMimicry == `true` {
		enableMimicry = true
	}

	_, err = genConfig(clientCfg{
		Secure:         form.Secure == `true`,
		Host:           form.Host,
		Port:           int(form.Port),
		Path:           form.Path,
		UUID:           strings.Repeat(`FF`, 16),
		Key:            strings.Repeat(`FF`, 32),
		EnableQUIC:     enableQUIC,
		QUICPort:       quicPort,
		EnableLongPoll: enableLongPoll,
		EnableDNS:      enableDNS,
		DNSDomain:      dnsDomain,
		DNSServer:      dnsServer,
		EnableMimicry:  enableMimicry,
	})
	if err != nil {
		if err == ErrTooLargeEntity {
			ctx.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, modules.Packet{Code: 1, Msg: `${i18n|GENERATOR.CONFIG_TOO_LARGE}`})
			return
		}
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: `${i18n|GENERATOR.CONFIG_GENERATE_FAILED}`})
		return
	}
	ctx.JSON(http.StatusOK, modules.Packet{Code: 0})
}

func GenerateClient(ctx *gin.Context) {
	var form struct {
		OS     string `json:"os" yaml:"os" form:"os" binding:"required"`
		Arch   string `json:"arch" yaml:"arch" form:"arch" binding:"required"`
		Host   string `json:"host" yaml:"host" form:"host" binding:"required"`
		Port   uint16 `json:"port" yaml:"port" form:"port" binding:"required"`
		Path   string `json:"path" yaml:"path" form:"path" binding:"required"`
		Secure string `json:"secure" yaml:"secure" form:"secure"`

		// Transport fallback options
		EnableQUIC     string `json:"enable_quic" yaml:"enable_quic" form:"enable_quic"`
		QUICPort       uint16 `json:"quic_port" yaml:"quic_port" form:"quic_port"`
		EnableLongPoll string `json:"enable_longpoll" yaml:"enable_longpoll" form:"enable_longpoll"`
		EnableDNS      string `json:"enable_dns" yaml:"enable_dns" form:"enable_dns"`
		DNSDomain      string `json:"dns_domain" yaml:"dns_domain" form:"dns_domain"`
		DNSServer      string `json:"dns_server" yaml:"dns_server" form:"dns_server"`
		EnableMimicry  string `json:"enable_mimicry" yaml:"enable_mimicry" form:"enable_mimicry"`
	}
	if err := ctx.ShouldBind(&form); err != nil {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	tpl, err := os.Open(fmt.Sprintf(servercfg.BuiltPath, form.OS, form.Arch))
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusNotFound, modules.Packet{Code: 1, Msg: `${i18n|GENERATOR.NO_PREBUILT_FOUND}`})
		return
	}
	defer tpl.Close()
	clientUUID := utils.GetUUID()
	clientKey, err := common.EncAES(clientUUID, servercfg.Config.SaltBytes)
	if err != nil {
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: `${i18n|GENERATOR.CONFIG_GENERATE_FAILED}`})
		return
	}
	// Use server config defaults when form doesn't specify transport settings
	enableQUIC := servercfg.Config.Transport.QUIC.Enable
	if form.EnableQUIC != "" {
		enableQUIC = form.EnableQUIC == `true`
	}

	enableLongPoll := servercfg.Config.Transport.LongPolling.Enable
	if form.EnableLongPoll != "" {
		enableLongPoll = form.EnableLongPoll == `true`
	}

	enableDNS := servercfg.Config.Transport.DNS.Enable
	if form.EnableDNS != "" {
		enableDNS = form.EnableDNS == `true`
	}

	// Use default QUIC port if not specified (defaults to main port)
	quicPort := int(form.Port)
	if form.QUICPort > 0 {
		quicPort = int(form.QUICPort)
	}

	// DNS domain from server config or form
	dnsDomain := servercfg.Config.Transport.DNS.Domain
	if form.DNSDomain != "" {
		dnsDomain = form.DNSDomain
	}

	// DNS server defaults to 8.8.8.8:53 if not specified
	dnsServer := "8.8.8.8:53"
	if form.DNSServer != "" {
		dnsServer = form.DNSServer
	}

	// Mimicry defaults to false
	enableMimicry := false
	if form.EnableMimicry == `true` {
		enableMimicry = true
	}

	cfgBytes, err := genConfig(clientCfg{
		Secure:         form.Secure == `true`,
		Host:           form.Host,
		Port:           int(form.Port),
		Path:           form.Path,
		UUID:           hex.EncodeToString(clientUUID),
		Key:            hex.EncodeToString(clientKey),
		EnableQUIC:     enableQUIC,
		QUICPort:       quicPort,
		EnableLongPoll: enableLongPoll,
		EnableDNS:      enableDNS,
		DNSDomain:      dnsDomain,
		DNSServer:      dnsServer,
		EnableMimicry:  enableMimicry,
	})
	if err != nil {
		if err == ErrTooLargeEntity {
			ctx.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, modules.Packet{Code: 1, Msg: `${i18n|GENERATOR.CONFIG_TOO_LARGE}`})
			return
		}
		ctx.AbortWithStatusJSON(http.StatusInternalServerError, modules.Packet{Code: 1, Msg: `${i18n|GENERATOR.CONFIG_GENERATE_FAILED}`})
		return
	}
	ctx.Header(`Accept-Ranges`, `none`)
	ctx.Header(`Content-Transfer-Encoding`, `binary`)
	ctx.Header(`Content-Type`, `application/octet-stream`)
	trailerFooter := clientcfg.BuildTrailerFooter(cfgBytes)
	if stat, err := tpl.Stat(); err == nil {
		total := stat.Size() + int64(len(cfgBytes)) + int64(clientcfg.TrailerFooterSize)
		ctx.Header(`Content-Length`, strconv.FormatInt(total, 10))
	}
	if form.OS == `windows` {
		ctx.Header(`Content-Disposition`, `attachment; filename=client.exe; filename*=UTF-8''client.exe`)
	} else {
		ctx.Header(`Content-Disposition`, `attachment; filename=client; filename*=UTF-8''client`)
	}
	io.Copy(ctx.Writer, tpl)
	ctx.Writer.Write(cfgBytes)
	ctx.Writer.Write(trailerFooter)
}

func genConfig(cfg clientCfg) ([]byte, error) {
	data, err := utils.JSON.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	key := utils.GetUUID()
	data, err = common.EncAES(data, key)
	if err != nil {
		return nil, err
	}
	final := append(key, data...)
	if len(final) > clientcfg.ConfigBufferSize-2 {
		return nil, ErrTooLargeEntity
	}

	// Get the length of encrypted buffer as a 2-byte big-endian integer.
	// And append encrypted buffer to the end of the data length.
	dataLen := big.NewInt(int64(len(final))).Bytes()
	dataLen = append(bytes.Repeat([]byte{'\x00'}, 2-len(dataLen)), dataLen...)

	// If the length of encrypted buffer is less than ConfigBufferSize,
	// append the remaining bytes with random bytes.
	final = append(dataLen, final...)
	for len(final) < clientcfg.ConfigBufferSize {
		final = append(final, utils.GetUUID()...)
	}
	return final[:clientcfg.ConfigBufferSize], nil
}
