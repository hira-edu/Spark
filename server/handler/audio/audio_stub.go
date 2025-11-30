package audio

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// InitAudio is a stub handler that responds with Not Implemented.
func InitAudio(ctx *gin.Context) {
	ctx.AbortWithStatusJSON(http.StatusNotImplemented, gin.H{
		`code`: -1,
		`msg`:  `${i18n|AUDIO.UNSUPPORTED}`,
	})
}
