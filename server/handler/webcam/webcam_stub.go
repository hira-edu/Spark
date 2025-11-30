package webcam

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// InitWebcam is a stub handler that responds with Not Implemented.
func InitWebcam(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(http.StatusNotImplemented, gin.H{
		`code`: -1,
		`msg`:  `${i18n|WEBCAM.UNSUPPORTED}`,
	})
}
