//go:build windows

package desktop

import (
	"errors"
	"fmt"
	"image"
	"strconv"
	"strings"

	"Rocket/client/config"

	"github.com/kirides/go-d3d"
	"github.com/kirides/go-d3d/dxgi"
	"golang.org/x/sys/windows"
)

type dxgiOutputSelection struct {
	AdapterIndex uint
	OutputIndex  uint
	OutputDesc   *dxgiOutputDesc
	AdapterDesc  *dxgiAdapterDesc1
}

func parseLUIDString(raw string) (*windows.LUID, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid LUID %q", raw)
	}
	high, err := strconv.ParseUint(parts[0], 16, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid LUID high %q: %w", parts[0], err)
	}
	low, err := strconv.ParseUint(parts[1], 16, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid LUID low %q: %w", parts[1], err)
	}
	return &windows.LUID{HighPart: int32(high), LowPart: uint32(low)}, nil
}

func intersectionArea(a, b image.Rectangle) int64 {
	inter := a.Intersect(b)
	if inter.Empty() {
		return 0
	}
	return int64(inter.Dx()) * int64(inter.Dy())
}

func rectFromDXGI(r dxgi.RECT) image.Rectangle {
	return image.Rect(int(r.Left), int(r.Top), int(r.Right), int(r.Bottom))
}

func distanceSquared(ax, ay, bx, by int64) int64 {
	dx := ax - bx
	dy := ay - by
	return dx*dx + dy*dy
}

// findDXGIOutputForRect enumerates all DXGI adapters/outputs and selects the
// output that best matches the provided desktop rectangle.
//
// Selection strategy:
//   - Prefer exact coordinate match.
//   - Otherwise, pick the output with the largest intersection area.
//   - If nothing intersects (DPI virtualization / transient topology), pick the
//     closest by center distance.
//   - If config.Config.Capture.AdapterLUID is set, give that adapter a strong bonus.
func findDXGIOutputForRect(target image.Rectangle) (*dxgiOutputSelection, error) {
	if target.Dx() <= 0 || target.Dy() <= 0 {
		return nil, fmt.Errorf("invalid target rect: %v", target)
	}

	var preferredLUID *windows.LUID
	if cfgLUID, err := parseLUIDString(config.Config.Capture.AdapterLUID); err == nil {
		preferredLUID = cfgLUID
	}

	var factory *dxgi.IDXGIFactory1
	if err := dxgi.CreateDXGIFactory1(&factory); err != nil {
		return nil, fmt.Errorf("CreateDXGIFactory1: %w", err)
	}
	defer factory.Release()

	var best *dxgiOutputSelection
	var bestScore int64 = -1

	targetCenterX := int64(target.Min.X+target.Max.X) / 2
	targetCenterY := int64(target.Min.Y+target.Max.Y) / 2

	for adapterIndex := uint(0); ; adapterIndex++ {
		var adapter *dxgi.IDXGIAdapter1
		hr := factory.EnumAdapters1(adapterIndex, &adapter)
		if d3d.HRESULT(hr) == d3d.DXGI_ERROR_NOT_FOUND {
			break
		}
		if d3d.HRESULT(hr).Failed() || adapter == nil {
			continue
		}

		adapterDesc, _ := queryDXGIAdapterDesc(adapter)
		preferredAdapter := false
		if preferredLUID != nil && adapterDesc != nil && adapterDesc.AdapterLuid == *preferredLUID {
			preferredAdapter = true
		}

		for outputIndex := uint(0); ; outputIndex++ {
			var output *dxgi.IDXGIOutput
			hr2 := int32(adapter.EnumOutputs(outputIndex, &output))
			if d3d.HRESULT(hr2) == d3d.DXGI_ERROR_NOT_FOUND {
				break
			}
			if d3d.HRESULT(hr2).Failed() || output == nil {
				continue
			}

			outputDesc, err := queryDXGIOutputDesc(output)
			output.Release()
			if err != nil || outputDesc == nil {
				continue
			}
			if outputDesc.AttachedToDesktop == 0 {
				continue
			}

			outRect := rectFromDXGI(outputDesc.DesktopCoordinates)
			area := intersectionArea(outRect, target)
			exact := outRect == target

			score := area
			if exact {
				score += 1 << 60
			}
			if preferredAdapter {
				score += 1 << 55
			}
			if area == 0 {
				outCenterX := int64(outRect.Min.X+outRect.Max.X) / 2
				outCenterY := int64(outRect.Min.Y+outRect.Max.Y) / 2
				dist := distanceSquared(outCenterX, outCenterY, targetCenterX, targetCenterY)
				score = (1 << 40) - dist
				if preferredAdapter {
					score += 1 << 35
				}
			}

			if best == nil || score > bestScore {
				bestScore = score
				best = &dxgiOutputSelection{
					AdapterIndex: adapterIndex,
					OutputIndex:  outputIndex,
					OutputDesc:   outputDesc,
					AdapterDesc:  adapterDesc,
				}
			}
		}

		adapter.Release()
	}

	if best == nil {
		return nil, errors.New("no DXGI outputs found")
	}
	return best, nil
}

func openDXGIAdapterOutput(sel *dxgiOutputSelection) (*dxgi.IDXGIAdapter1, *dxgi.IDXGIOutput, error) {
	if sel == nil {
		return nil, nil, errors.New("nil selection")
	}

	var factory *dxgi.IDXGIFactory1
	if err := dxgi.CreateDXGIFactory1(&factory); err != nil {
		return nil, nil, fmt.Errorf("CreateDXGIFactory1: %w", err)
	}
	defer factory.Release()

	var adapter *dxgi.IDXGIAdapter1
	hr := factory.EnumAdapters1(sel.AdapterIndex, &adapter)
	if d3d.HRESULT(hr).Failed() || adapter == nil {
		return nil, nil, fmt.Errorf("EnumAdapters1(%d): %w", sel.AdapterIndex, d3d.HRESULT(hr))
	}

	var output *dxgi.IDXGIOutput
	hr2 := int32(adapter.EnumOutputs(sel.OutputIndex, &output))
	if d3d.HRESULT(hr2).Failed() || output == nil {
		adapter.Release()
		return nil, nil, fmt.Errorf("EnumOutputs(%d): %w", sel.OutputIndex, d3d.HRESULT(hr2))
	}

	return adapter, output, nil
}
