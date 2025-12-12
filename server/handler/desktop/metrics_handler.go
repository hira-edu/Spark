package desktop

import (
	"net/http"

	"Rocket/modules"

	"github.com/gin-gonic/gin"
)

// GetDesktopMetrics exposes the latest desktop metrics snapshot for a given desktop UUID.
func GetDesktopMetrics(ctx *gin.Context) {
	desktopUUID := ctx.Query("desktop")
	if desktopUUID == "" {
		ctx.JSON(http.StatusBadRequest, modules.Packet{
			Code: 1,
			Msg:  "missing desktop parameter",
		})
		return
	}

	if envelope, ok := getDesktopMetrics(desktopUUID); ok {
		ctx.JSON(http.StatusOK, modules.Packet{
			Code: 0,
			Data: gin.H{
				"metrics":  envelope,
				"counters": desktopCounterSnapshot(),
			},
		})
		return
	}

	ctx.JSON(http.StatusOK, modules.Packet{
		Code: 0,
		Data: gin.H{
			"metrics":  nil,
			"counters": desktopCounterSnapshot(),
		},
	})
}
