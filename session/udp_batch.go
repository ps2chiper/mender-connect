package session

import (
	"encoding/binary"
	"errors"
	"time"
)

const (
	udpBatchFrame  = 256 * 1024
	udpMaxDatagram = 65507
	udpBatchCount  = 64
	udpBatchDelay  = 12 * time.Millisecond
)

// Each entry has a two-byte big-endian length. A zero length denotes an empty datagram.
func appendDatagram(frame, packet []byte) []byte {
	if frame == nil {
		frame = make([]byte, 2)
	}
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(packet)))
	return append(frame, packet...)
}

// The first two bytes record the collection span in microseconds. Replay
// small groups over half that span to absorb WAN bursts with catch-up room.
func finishBatch(frame []byte, started time.Time) []byte {
	elapsed := min(time.Since(started), udpBatchDelay)
	binary.BigEndian.PutUint16(frame[:2], uint16(elapsed.Microseconds()))
	return frame
}

func paceGroup(start time.Time, frame []byte, index, total int) {
	if index == 0 || index%4 != 0 {
		return
	}
	span := time.Duration(binary.BigEndian.Uint16(frame[:2])) * time.Microsecond
	time.Sleep(time.Until(start.Add(span * time.Duration(index) / time.Duration(2*total))))
}

// Validate the complete frame before delivering even its first packet.
func splitDatagrams(frame []byte) ([][]byte, error) {
	if len(frame) < 4 || len(frame) > udpBatchFrame || binary.BigEndian.Uint16(frame[:2]) > uint16(udpBatchDelay.Microseconds()) {
		return nil, errors.New("invalid UDP batch size")
	}
	frame = frame[2:]
	packets := make([][]byte, 0, udpBatchCount)
	for len(frame) > 0 {
		if len(frame) < 2 || len(packets) == udpBatchCount {
			return nil, errors.New("invalid UDP batch")
		}
		n := int(binary.BigEndian.Uint16(frame))
		frame = frame[2:]
		if n > udpMaxDatagram || n > len(frame) {
			return nil, errors.New("invalid UDP datagram length")
		}
		packets = append(packets, frame[:n])
		frame = frame[n:]
	}
	return packets, nil
}
