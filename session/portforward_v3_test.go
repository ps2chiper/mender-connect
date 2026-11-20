// Copyright 2026 Northern.tech AS
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.

package session

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mendersoftware/go-lib-micro/ws"
	wspf "github.com/mendersoftware/go-lib-micro/ws/portforward"
	"github.com/stretchr/testify/assert"
	"github.com/vmihailenco/msgpack/v5"
)

type v3TestWriter struct {
	mu       sync.Mutex
	messages []*ws.ProtoMsg
	created  chan *ws.ProtoMsg
}

func newV3TestWriter() *v3TestWriter {
	return &v3TestWriter{created: make(chan *ws.ProtoMsg, 32)}
}

func (w *v3TestWriter) WriteProtoMsg(msg *ws.ProtoMsg) error {
	w.mu.Lock()
	w.messages = append(w.messages, msg)
	w.mu.Unlock()
	select {
	case w.created <- msg:
	default:
	}
	return nil
}

func (w *v3TestWriter) waitFor(
	t *testing.T,
	match func(*ws.ProtoMsg) bool,
	timeout time.Duration,
) *ws.ProtoMsg {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case msg := <-w.created:
			if match(msg) {
				return msg
			}
		case <-deadline:
			t.Fatal("timed out waiting for v3 message")
			return nil
		}
	}
}

func v3NewRequest(t *testing.T, host string, port uint16, id string) *ws.ProtoMsg {
	t.Helper()
	protocol := wspf.PortForwardProtocol(wspf.PortForwardProtocolTCP)
	body, err := msgpack.Marshal(&portForwardNewV3{
		RemoteHost:      &host,
		RemotePort:      &port,
		Protocol:        &protocol,
		FlowControl:     true,
		TCPFrameSize:    32 * 1024,
		TCPMaxFrameSize: portForwardV3MaxFrameSize,
	})
	assert.NoError(t, err)
	return &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ProtoTypePortForwardV3,
			MsgType:   wspf.MessageTypePortForwardNew,
			SessionID: "v3-session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: id,
			},
		},
		Body: body,
	}
}

func TestPortForwardV3NegotiatesLargeFrames(t *testing.T) {
	handler := PortForwardV3()()
	tcpPort, closeTCPServer := echoTCPServer(t)
	defer closeTCPServer()

	w := newV3TestWriter()
	handler.ServeProtoMsg(v3NewRequest(t, "localhost", uint16(tcpPort), "c1"), w)

	response := w.waitFor(t, func(msg *ws.ProtoMsg) bool {
		return msg.Header.MsgType == wspf.MessageTypePortForwardNew
	}, 5*time.Second)
	var accepted struct {
		TCPFrameSize uint32 `msgpack:"tcp_frame_size"`
	}
	assert.NoError(t, msgpack.Unmarshal(response.Body, &accepted))
	assert.Equal(t, uint32(portForwardV3FrameSize), accepted.TCPFrameSize)

	payload := bytes.Repeat([]byte("v3"), 16*1024)
	handler.ServeProtoMsg(&ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ProtoTypePortForwardV3,
			MsgType:   wspf.MessageTypePortForward,
			SessionID: "v3-session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c1",
			},
		},
		Body: payload,
	}, w)

	echoed := make([]byte, 0, len(payload))
	var ack *ws.ProtoMsg
	deadline := time.After(10 * time.Second)
	for len(echoed) < len(payload) || ack == nil {
		select {
		case msg := <-w.created:
			switch msg.Header.MsgType {
			case wspf.MessageTypePortForwardAck:
				ack = msg
			case wspf.MessageTypePortForward:
				echoed = append(echoed, msg.Body...)
			}
		case <-deadline:
			t.Fatal("timed out waiting for v3 echo/ack")
		}
	}
	assert.Len(t, ack.Body, 4)
	assert.Equal(t, uint32(1), binary.BigEndian.Uint32(ack.Body))
	assert.Equal(t, payload, echoed)

	assert.NoError(t, handler.Close())
}

func TestPortForwardV3HalfClosePreservesResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	assert.NoError(t, err)
	defer listener.Close()

	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		data, _ := io.ReadAll(conn)
		_, _ = conn.Write(append([]byte("after-eof:"), data...))
		_ = conn.(*net.TCPConn).CloseWrite()
	}()

	handler := PortForwardV3()()
	w := newV3TestWriter()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)
	handler.ServeProtoMsg(v3NewRequest(t, "127.0.0.1", port, "c-half"), w)
	w.waitFor(t, func(msg *ws.ProtoMsg) bool {
		return msg.Header.MsgType == wspf.MessageTypePortForwardNew
	}, 5*time.Second)

	payload := []byte("request")
	handler.ServeProtoMsg(&ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ProtoTypePortForwardV3,
			MsgType:   wspf.MessageTypePortForward,
			SessionID: "v3-session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c-half",
			},
		},
		Body: payload,
	}, w)

	handler.ServeProtoMsg(&ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ProtoTypePortForwardV3,
			MsgType:   messageTypePortForwardHalfClose,
			SessionID: "v3-session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c-half",
			},
		},
	}, w)

	var response []byte
	for {
		msg := w.waitFor(t, func(msg *ws.ProtoMsg) bool {
			return msg.Header.MsgType == wspf.MessageTypePortForward ||
				msg.Header.MsgType == messageTypePortForwardHalfClose
		}, 10*time.Second)
		if msg.Header.MsgType == messageTypePortForwardHalfClose {
			break
		}
		response = append(response, msg.Body...)
	}
	assert.Equal(t, append([]byte("after-eof:"), payload...), response)
	select {
	case <-targetDone:
	case <-time.After(5 * time.Second):
		t.Fatal("target did not finish after half-close")
	}

	assert.NoError(t, handler.Close())
}

func TestV3FrameSize(t *testing.T) {
	cases := []struct {
		name string
		req  portForwardNewV3
		want int
	}{
		{"max", portForwardNewV3{TCPMaxFrameSize: portForwardV3MaxFrameSize}, portForwardV3FrameSize},
		{"frame", portForwardNewV3{TCPFrameSize: 32 * 1024}, 32 * 1024},
		{"default", portForwardNewV3{}, portForwardBuffSize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, v3FrameSize(&tc.req))
		})
	}
}
