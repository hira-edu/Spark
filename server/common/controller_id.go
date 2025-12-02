package common

import "sync/atomic"

var controllerID atomic.Value

// SetControllerID sets the global controller identifier for this server instance.
func SetControllerID(id string) {
	controllerID.Store(id)
}

// GetControllerID returns the controller identifier, or an empty string if unset.
func GetControllerID() string {
	if v := controllerID.Load(); v != nil {
		return v.(string)
	}
	return ""
}
