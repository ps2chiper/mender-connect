package session

import (
	"bytes"
	"testing"
)

func TestUDPBatchWireFormat(t *testing.T) {
	frame := appendDatagram(nil, nil)
	frame = appendDatagram(frame, []byte{42})
	if !bytes.Equal(frame, []byte{0, 0, 0, 0, 0, 1, 42}) {
		t.Fatal(frame)
	}
	pkts, err := splitDatagrams(frame)
	if err != nil || len(pkts) != 2 || len(pkts[0]) != 0 || !bytes.Equal(pkts[1], []byte{42}) {
		t.Fatal(pkts, err)
	}
	for _, bad := range [][]byte{nil, {0}, {0, 1, 42, 0}, {0, 2, 42}, make([]byte, 132)} {
		if _, err = splitDatagrams(bad); err == nil {
			t.Fatalf("accepted malformed batch of %d bytes", len(bad))
		}
	}
}
