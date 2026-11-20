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

	"context"
	"crypto/sha256"
	"github.com/mendersoftware/go-lib-micro/ws"
	wspf "github.com/mendersoftware/go-lib-micro/ws/portforward"
	"github.com/stretchr/testify/assert"
	"github.com/vmihailenco/msgpack/v5"
	"math/rand"
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

func (w *v3TestWriter) take(t *testing.T, n int) []*ws.ProtoMsg {
	t.Helper()
	msgs := make([]*ws.ProtoMsg, 0, n)
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for len(msgs) < n {
		select {
		case msg := <-w.created:
			msgs = append(msgs, msg)
		case <-timer.C:
			t.Fatalf("received %d of %d messages", len(msgs), n)
		}
	}
	return msgs
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
		{"default", portForwardNewV3{}, portForwardV3DefaultFrame},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, v3FrameSize(&tc.req))
		})
	}
}

// Readers may return bytes and EOF in the same call.
type finalReadConn struct{ net.Conn }

func (c finalReadConn) Read(p []byte) (int, error) { return copy(p, "tail"), io.EOF }

func TestPortForwardV3DataBeforeEOF(t *testing.T) {
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	w := newV3TestWriter()
	f := MenderPortForwarder{proto: ProtoTypePortForwardV3, conn: finalReadConn{left}, frameSize: 4096, ctx: context.Background(), ResponseWriter: w}
	f.Read()
	if !assert.Len(t, w.messages, 2) {
		return
	}
	assert.Equal(t, wspf.MessageTypePortForward, w.messages[0].Header.MsgType)
	assert.Equal(t, []byte("tail"), w.messages[0].Body)
	assert.Equal(t, messageTypePortForwardHalfClose, w.messages[1].Header.MsgType)
}

func TestPortForwardV3EnforcesNegotiatedSize(t *testing.T) {
	port, stop := echoTCPServer(t)
	defer stop()
	h := PortForwardV3()()
	defer h.Close()
	w := newV3TestWriter()
	m := v3NewRequest(t, "127.0.0.1", uint16(port), "small")
	var offer portForwardNewV3
	if err := msgpack.Unmarshal(m.Body, &offer); err != nil {
		t.Fatal(err)
	}
	offer.TCPMaxFrameSize = 0
	offer.TCPFrameSize = 32768
	m.Body, _ = msgpack.Marshal(offer)
	h.ServeProtoMsg(m, w)
	assert.Equal(t, wspf.MessageTypePortForwardNew, w.take(t, 1)[0].Header.MsgType)
	m.Header.MsgType = wspf.MessageTypePortForward
	m.Body = make([]byte, 32769)
	h.ServeProtoMsg(m, w)
	reply := w.take(t, 1)[0]
	assert.Equal(t, wspf.MessageTypeError, reply.Header.MsgType)
	assert.Equal(t, "small", reply.Header.Properties[wspf.PropertyConnectionID])
}

func TestPortForwardV3CreditWindow(t *testing.T) {
	left, right := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer left.Close()
	defer right.Close()
	w := newV3TestWriter()
	f := &MenderPortForwarder{proto: ProtoTypePortForwardV3, conn: left, ctx: ctx, frameSize: 1, ResponseWriter: w, credits: make(chan struct{}, portForwardV3Window)}
	for i := 0; i < cap(f.credits); i++ {
		f.credits <- struct{}{}
	}
	h := &PortForwardHandler{proto: ProtoTypePortForwardV3, portForwarders: map[string]*MenderPortForwarder{"c": f}}
	go f.Read()
	go func() { _, _ = right.Write(make([]byte, portForwardV3Window+2)) }()
	for i := 0; i < portForwardV3Window; i++ {
		w.waitFor(t, func(m *ws.ProtoMsg) bool { return m.Header.MsgType == wspf.MessageTypePortForward }, time.Second)
	}
	select {
	case <-w.created:
		t.Fatal("sent past the negotiated window")
	case <-time.After(20 * time.Millisecond):
	}
	ack := &ws.ProtoMsg{Header: ws.ProtoHdr{Proto: h.proto, MsgType: wspf.MessageTypePortForwardAck, Properties: map[string]interface{}{wspf.PropertyConnectionID: "c"}}, Body: []byte{0, 0, 0, 2}}
	h.ServeProtoMsg(ack, w)
	for i := 0; i < 2; i++ {
		w.waitFor(t, func(m *ws.ProtoMsg) bool { return m.Header.MsgType == wspf.MessageTypePortForward }, time.Second)
	}
}

func TestPortForwardV3AcknowledgesNewBeforeGreeting(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	h := PortForwardV3()()
	defer h.Close()
	w := newV3TestWriter()
	acceptStarted := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	writer := ResponseWriterFunc(func(m *ws.ProtoMsg) error {
		if m.Header.MsgType == wspf.MessageTypePortForwardNew {
			close(acceptStarted)
			<-release
		}
		return w.WriteProtoMsg(m)
	})
	req := v3NewRequest(t, "127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port), "greet")
	go h.ServeProtoMsg(req, writer)
	_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(3 * time.Second))
	target, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	_, err = target.Write([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-acceptStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("missing new reply")
	}
	select {
	case m := <-w.created:
		t.Fatalf("%s before new reply", m.Header.MsgType)
	case <-time.After(20 * time.Millisecond):
	}
	unblock()
	msgs := w.take(t, 2)
	assert.Equal(t, wspf.MessageTypePortForwardNew, msgs[0].Header.MsgType)
	assert.Equal(t, []byte("hello"), msgs[1].Body)
}

// The target waits for request EOF, then replies with the entire payload.
// Each direction must pass through more than one full v3 credit window.
func TestPortForwardV3BulkRoundTrip(t *testing.T) {
	payload := make([]byte, 8*1024*1024)
	_, _ = rand.New(rand.NewSource(267)).Read(payload)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		c, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(10 * time.Second))
		body, err := io.ReadAll(io.LimitReader(c, int64(len(payload))+1))
		if err == nil {
			_, err = c.Write(body)
		}
		done <- err
	}()
	h := PortForwardV3()()
	defer h.Close()
	out := make(chan *ws.ProtoMsg, 32)
	writer := ResponseWriterFunc(func(m *ws.ProtoMsg) error { out <- m; return nil })
	req := v3NewRequest(t, "127.0.0.1", uint16(listener.Addr().(*net.TCPAddr).Port), "bulk")
	h.ServeProtoMsg(req, writer)
	receive := func() *ws.ProtoMsg {
		t.Helper()
		select {
		case m := <-out:
			return m
		case <-time.After(10 * time.Second):
			t.Fatal("timeout receiving bulk frame")
			return nil
		}
	}
	if !assert.Equal(t, wspf.MessageTypePortForwardNew, receive().Header.MsgType) {
		return
	}
	send := func(kind string, body []byte) {
		hdr := req.Header
		hdr.MsgType = kind
		h.ServeProtoMsg(&ws.ProtoMsg{Header: hdr, Body: body}, writer)
	}
	for offset := 0; offset < len(payload); offset += portForwardV3FrameSize {
		send(wspf.MessageTypePortForward, payload[offset:offset+portForwardV3FrameSize])
		m := receive()
		if !assert.Equal(t, wspf.MessageTypePortForwardAck, m.Header.MsgType) || !assert.Equal(t, []byte{0, 0, 0, 1}, m.Body) {
			return
		}
	}
	send(messageTypePortForwardHalfClose, nil)
	hash := sha256.New()
	count := 0
	received := 0
	for {
		m := receive()
		if m.Header.MsgType == messageTypePortForwardHalfClose {
			break
		}
		if !assert.Equal(t, wspf.MessageTypePortForward, m.Header.MsgType) {
			return
		}
		hash.Write(m.Body)
		received += len(m.Body)
		count++
		if count%4 == 0 {
			send(wspf.MessageTypePortForwardAck, []byte{0, 0, 0, 4})
		}
	}
	expected := sha256.Sum256(payload)
	assert.Equal(t, len(payload), received)
	assert.Equal(t, expected[:], hash.Sum(nil))
	assert.NoError(t, <-done)
}
