package rendezvous

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const deviceContextKey = "deviceUUID"

// DeviceAuthMiddleware enforces UUID/Key authentication for rendezvous endpoints.
func DeviceAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		uuidHex := strings.TrimSpace(c.GetHeader("UUID"))
		keyHex := strings.TrimSpace(c.GetHeader("Key"))
		if uuidHex == "" || keyHex == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing device credentials"})
			return
		}

		uuid, err := hex.DecodeString(uuidHex)
		if err != nil || len(uuid) != 16 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid device UUID"})
			return
		}

		keyBytes, err := hex.DecodeString(keyHex)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid device key"})
			return
		}

		var authValid bool
		switch len(keyBytes) {
		case 16:
			authValid = bytes.Equal(keyBytes, uuid)
		case 32:
			authValid = bytes.Equal(keyBytes[:16], uuid)
		}

		if !authValid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "authentication failed"})
			return
		}

		c.Set(deviceContextKey, strings.ToLower(uuidHex))
		c.Next()
	}
}

func getAuthenticatedPeerID(c *gin.Context) (string, bool) {
	peerID, ok := c.Get(deviceContextKey)
	if !ok {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return "", false
	}
	return peerID.(string), true
}
