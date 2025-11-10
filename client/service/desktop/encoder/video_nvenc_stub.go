//go:build !windows

package encoder

type adapterCandidate struct{}

func registerNVENCFactory(_ *Manager, _ *adapterCandidate) {}
