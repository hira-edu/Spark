package utility

import (
	"Rocket/server/cluster"
	"Rocket/server/common"
	"net/http"

	"github.com/gin-gonic/gin"
)

// GetClusterStatus returns a lightweight snapshot of cluster state and metrics.
func GetClusterStatus(ctx *gin.Context) {
	mgr := cluster.Current()
	if mgr == nil {
		ctx.JSON(http.StatusOK, gin.H{
			`enabled`:      false,
			`controllerId`: common.GetControllerID(),
		})
		return
	}

	ctx.JSON(http.StatusOK, gin.H{
		`enabled`: true,
		`stats`:   mgr.Stats(ctx),
	})
}
