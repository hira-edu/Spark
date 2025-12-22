package desktop

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/pion/sdp/v3"
)

type h264FmtpSelection struct {
	FmtpLine   string
	ProfileID  uint8
	Constraint uint8
	LevelID    uint8
}

type h264FmtpCandidate struct {
	fmtpLine   string
	profileID  uint8
	constraint uint8
	levelID    uint8
}

func selectH264FmtpFromOffer(sdpStr string) (h264FmtpSelection, error) {
	var desc sdp.SessionDescription
	if err := desc.Unmarshal([]byte(sdpStr)); err != nil {
		return h264FmtpSelection{}, fmt.Errorf("parse SDP: %w", err)
	}

	var video *sdp.MediaDescription
	for _, md := range desc.MediaDescriptions {
		if md.MediaName.Media == "video" {
			video = md
			break
		}
	}
	if video == nil {
		return h264FmtpSelection{}, errors.New("no video media section in SDP")
	}

	h264Payloads := map[string]struct{}{}
	for _, attr := range video.Attributes {
		if attr.Key != "rtpmap" {
			continue
		}
		parts := strings.Fields(attr.Value)
		if len(parts) < 2 {
			continue
		}
		pt := strings.TrimSpace(parts[0])
		if pt == "" {
			continue
		}
		codec := strings.ToLower(parts[1])
		if strings.HasPrefix(codec, "h264/") || codec == "h264" {
			h264Payloads[pt] = struct{}{}
		}
	}
	if len(h264Payloads) == 0 {
		return h264FmtpSelection{}, errors.New("no H264 payloads in SDP")
	}

	candidates := make([]h264FmtpCandidate, 0, 4)
	for _, attr := range video.Attributes {
		if attr.Key != "fmtp" {
			continue
		}
		fields := strings.Fields(attr.Value)
		if len(fields) < 2 {
			continue
		}
		pt := strings.TrimSpace(fields[0])
		if _, ok := h264Payloads[pt]; !ok {
			continue
		}
		params := parseFmtpParams(strings.Join(fields[1:], " "))
		if strings.TrimSpace(params["packetization-mode"]) != "1" {
			continue
		}
		profileHex := strings.ToLower(strings.TrimSpace(params["profile-level-id"]))
		if profileHex == "" {
			continue
		}
		profileID, constraint, levelID, ok := parseProfileLevelID(profileHex)
		if !ok {
			continue
		}
		candidates = append(candidates, h264FmtpCandidate{
			fmtpLine:   buildH264FmtpLine(profileHex, params),
			profileID:  profileID,
			constraint: constraint,
			levelID:    levelID,
		})
	}
	if len(candidates) == 0 {
		return h264FmtpSelection{}, errors.New("no compatible H264 fmtp line found (packetization-mode=1)")
	}

	bestIdx := 0
	bestRank := h264ProfileRank(candidates[0].profileID)
	bestConstraintRank := h264ConstraintRank(candidates[0].profileID, candidates[0].constraint)
	for i := 1; i < len(candidates); i++ {
		rank := h264ProfileRank(candidates[i].profileID)
		constraintRank := h264ConstraintRank(candidates[i].profileID, candidates[i].constraint)
		if rank < bestRank || (rank == bestRank && constraintRank < bestConstraintRank) {
			bestRank = rank
			bestConstraintRank = constraintRank
			bestIdx = i
		}
	}
	best := candidates[bestIdx]
	return h264FmtpSelection{
		FmtpLine:   best.fmtpLine,
		ProfileID:  best.profileID,
		Constraint: best.constraint,
		LevelID:    best.levelID,
	}, nil
}

func parseFmtpParams(raw string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, val, found := strings.Cut(part, "=")
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.TrimSpace(val)
		if key == "" {
			continue
		}
		if found {
			out[key] = val
		}
	}
	return out
}

func buildH264FmtpLine(profileHex string, params map[string]string) string {
	levelAsym := strings.TrimSpace(params["level-asymmetry-allowed"])
	if levelAsym == "" {
		levelAsym = "1"
	}
	pMode := strings.TrimSpace(params["packetization-mode"])
	if pMode == "" {
		pMode = "1"
	}
	profileHex = strings.ToLower(profileHex)
	return fmt.Sprintf("level-asymmetry-allowed=%s;packetization-mode=%s;profile-level-id=%s", levelAsym, pMode, profileHex)
}

func parseProfileLevelID(raw string) (uint8, uint8, uint8, bool) {
	raw = strings.TrimSpace(raw)
	if len(raw) < 6 {
		return 0, 0, 0, false
	}
	buf, err := hex.DecodeString(raw[:6])
	if err != nil || len(buf) < 3 {
		return 0, 0, 0, false
	}
	return buf[0], buf[1], buf[2], true
}

func h264ProfileRank(profileID uint8) int {
	switch profileID {
	case 0x42:
		return 0 // baseline
	case 0x4d:
		return 1 // main
	case 0x64:
		return 2 // high
	default:
		return 3
	}
}

func h264ConstraintRank(profileID, constraint uint8) int {
	// Prefer constrained baseline (0x42e0xx) when available for best decoder compatibility.
	if profileID != 0x42 {
		return 0
	}
	switch constraint {
	case 0xE0:
		return 0
	case 0x80:
		return 1
	default:
		return 2
	}
}
