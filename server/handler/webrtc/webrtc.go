package webrtc

import (
	"Rocket/modules"
	"Rocket/server/common"
	servercfg "Rocket/server/config"
	"Rocket/server/handler/utility"
	"Rocket/utils"
	"Rocket/utils/melody"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	maxSDPLength       = 1 << 15 // 32 KiB
	maxCandidateLength = 4096
)

type sdpForm struct {
	SDP     string `json:"sdp" binding:"required"`
	Desktop string `json:"desktop"`
	Role    string `json:"role"`
	Retry   int    `json:"retry"`
}

type iceForm struct {
	Candidate     string `json:"candidate" binding:"required"`
	SDPMid        string `json:"sdpMid"`
	SDPMLineIndex int    `json:"sdpMLineIndex"`
	Desktop       string `json:"desktop"`
	Role          string `json:"role"`
	Retry         int    `json:"retry"`
}

// Offer relays a browser offer to the device and awaits acknowledgement.
func Offer(ctx *gin.Context) {
	var form sdpForm
	target, ok := utility.CheckForm(ctx, &form)
	if !ok {
		return
	}
	if len(form.SDP) == 0 || len(form.SDP) > maxSDPLength {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	// Validate SDP format
	if !isValidSDP(form.SDP) {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	trigger := utils.GetStrUUID()
	payload := gin.H{`sdp`: form.SDP, `type`: `offer`}
	if len(form.Desktop) > 0 {
		payload[`desktop`] = form.Desktop
	}
	if form.Role != "" {
		payload[`role`] = form.Role
	}
	if form.Retry > 0 {
		payload[`retry`] = form.Retry
	}
	if !common.SendPackByUUID(modules.Packet{Act: `DESKTOP_WEBRTC_OFFER`, Data: payload, Event: trigger}, target) {
		ctx.AbortWithStatusJSON(http.StatusBadGateway, modules.Packet{Code: 1, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`})
		return
	}
	ok = common.AddEventOnce(func(p modules.Packet, _ *melody.Session) {
		if p.Code != 0 {
			ctx.AbortWithStatusJSON(http.StatusBadGateway, modules.Packet{Code: p.Code, Msg: p.Msg})
			return
		}
		ctx.JSON(http.StatusOK, modules.Packet{
			Code: 0,
			Data: gin.H{
				`ice`:  iceServers(),
				`resp`: p.Data,
			},
		})
	}, target, trigger, 10*time.Second)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusGatewayTimeout, modules.Packet{Code: 1, Msg: `${i18n|COMMON.RESPONSE_TIMEOUT}`})
	}
}

// Answer relays a browser answer to the device and awaits acknowledgement.
func Answer(ctx *gin.Context) {
	var form sdpForm
	target, ok := utility.CheckForm(ctx, &form)
	if !ok {
		return
	}
	if len(form.SDP) == 0 || len(form.SDP) > maxSDPLength {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	// Validate SDP format
	if !isValidSDP(form.SDP) {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	trigger := utils.GetStrUUID()
	payload := gin.H{`sdp`: form.SDP, `type`: `answer`}
	if len(form.Desktop) > 0 {
		payload[`desktop`] = form.Desktop
	}
	if form.Role != "" {
		payload[`role`] = form.Role
	}
	if form.Retry > 0 {
		payload[`retry`] = form.Retry
	}
	if !common.SendPackByUUID(modules.Packet{Act: `DESKTOP_WEBRTC_ANSWER`, Data: payload, Event: trigger}, target) {
		ctx.AbortWithStatusJSON(http.StatusBadGateway, modules.Packet{Code: 1, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`})
		return
	}
	ok = common.AddEventOnce(func(p modules.Packet, _ *melody.Session) {
		if p.Code != 0 {
			ctx.AbortWithStatusJSON(http.StatusBadGateway, modules.Packet{Code: p.Code, Msg: p.Msg})
			return
		}
		ctx.JSON(http.StatusOK, modules.Packet{
			Code: 0,
			Data: gin.H{
				`ice`:  iceServers(),
				`resp`: p.Data,
			},
		})
	}, target, trigger, 10*time.Second)
	if !ok {
		ctx.AbortWithStatusJSON(http.StatusGatewayTimeout, modules.Packet{Code: 1, Msg: `${i18n|COMMON.RESPONSE_TIMEOUT}`})
	}
}

// ICE relays ICE candidates to the device without waiting for acknowledgement.
func ICE(ctx *gin.Context) {
	var form iceForm
	target, ok := utility.CheckForm(ctx, &form)
	if !ok {
		return
	}
	if len(form.Candidate) == 0 || len(form.Candidate) > maxCandidateLength {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	// Validate ICE candidate format
	if !isValidICECandidate(form.Candidate) {
		ctx.AbortWithStatusJSON(http.StatusBadRequest, modules.Packet{Code: -1, Msg: `${i18n|COMMON.INVALID_PARAMETER}`})
		return
	}
	payload := gin.H{
		`candidate`: form.Candidate,
		`sdpMid`:    form.SDPMid,
		`mLine`:     form.SDPMLineIndex, // Use consistent field name with client
	}
	if len(form.Desktop) > 0 {
		payload[`desktop`] = form.Desktop
	}
	if form.Role != "" {
		payload[`role`] = form.Role
	}
	if form.Retry > 0 {
		payload[`retry`] = form.Retry
	}
	if !common.SendPackByUUID(modules.Packet{Act: `DESKTOP_WEBRTC_ICE`, Data: payload}, target) {
		ctx.AbortWithStatusJSON(http.StatusBadGateway, modules.Packet{Code: 1, Msg: `${i18n|COMMON.DEVICE_NOT_EXIST}`})
		return
	}
	ctx.JSON(http.StatusOK, modules.Packet{
		Code: 0,
		Data: gin.H{`ice`: iceServers()},
	})
}

// isValidICECandidate performs basic validation on ICE candidate format
func isValidICECandidate(candidate string) bool {
	if candidate == "" {
		return true // Empty candidate signals end-of-candidates
	}
	// ICE candidates contain space-separated components and type info
	return strings.Contains(candidate, " ") &&
		(strings.HasPrefix(candidate, "candidate:") || strings.Contains(candidate, "typ "))
}

// isValidSDP performs basic validation on SDP format
func isValidSDP(sdp string) bool {
	if sdp == "" {
		return false
	}
	// SDP must contain version line and at least one media section
	return strings.Contains(sdp, "v=") && strings.Contains(sdp, "m=")
}

// Config returns the ICE server configuration (currently TURN only).
func Config(ctx *gin.Context) {
	ctx.JSON(http.StatusOK, modules.Packet{
		Code: 0,
		Data: gin.H{`ice`: iceServers()},
	})
}

func iceServers() gin.H {
	if servercfg.Config.WebRTC == nil {
		return gin.H{
			`turn`: []string{},
			`stun`: []string{},
		}
	}
	return gin.H{
		`turn`: servercfg.Config.WebRTC.Turn,
		`stun`: servercfg.Config.WebRTC.Stun,
	}
}
