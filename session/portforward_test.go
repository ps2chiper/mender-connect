// Copyright 2023 Northern.tech AS
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
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/mendersoftware/go-lib-micro/ws"
	wspf "github.com/mendersoftware/go-lib-micro/ws/portforward"
	"github.com/stretchr/testify/assert"
	"github.com/vmihailenco/msgpack/v5"
)

func getFreeTCPPort() int {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	return listener.Addr().(*net.TCPAddr).Port
}

func TestPortForwardHandler(t *testing.T) {
	handler := PortForward()()

	// unkonwn message
	msg := &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:   ws.ProtoTypePortForward,
			MsgType: "dummy",
		},
	}
	w := new(testWriter)
	handler.ServeProtoMsg(msg, w)
	if !assert.Len(t, w.Messages, 1) {
		t.FailNow()
	}
	rsp := w.Messages[0]
	assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
	assert.Equal(t, wspf.MessageTypeError, rsp.Header.MsgType)

	msgError := &wspf.Error{}
	_ = msgpack.Unmarshal(rsp.Body, msgError)
	assert.Equal(t, errPortForwardUnkonwnMessageType.Error(), *msgError.Error)

	// new
	protocol := wspf.PortForwardProtocol(wspf.PortForwardProtocolTCP)
	remoteHost := "localhost"
	remotePort := uint16(getFreeTCPPort())
	portForwardNew := &wspf.PortForwardNew{
		Protocol:   &protocol,
		RemoteHost: &remoteHost,
		RemotePort: &remotePort,
	}
	body, _ := msgpack.Marshal(portForwardNew)
	msg = &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypePortForward,
			MsgType:   wspf.MessageTypePortForwardNew,
			SessionID: "session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c1",
			},
		},
		Body: body,
	}
	w = new(testWriter)
	handler.ServeProtoMsg(msg, w)
	if !assert.Len(t, w.Messages, 1) {
		t.FailNow()
	}
	rsp = w.Messages[0]
	assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
	assert.Equal(t, wspf.MessageTypeError, rsp.Header.MsgType)

	msgError = &wspf.Error{}
	_ = msgpack.Unmarshal(rsp.Body, msgError)
	assert.Contains(t, *msgError.Error, "connect: connection refused")

	// new - unknown protocol
	protocol = "dummy"
	remoteHost = "localhost"
	remotePort = uint16(getFreeTCPPort())
	portForwardNew = &wspf.PortForwardNew{
		Protocol:   &protocol,
		RemoteHost: &remoteHost,
		RemotePort: &remotePort,
	}
	body, _ = msgpack.Marshal(portForwardNew)
	msg = &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypePortForward,
			MsgType:   wspf.MessageTypePortForwardNew,
			SessionID: "session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c1",
			},
		},
		Body: body,
	}
	w = new(testWriter)
	handler.ServeProtoMsg(msg, w)
	if !assert.Len(t, w.Messages, 1) {
		t.FailNow()
	}
	rsp = w.Messages[0]
	assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
	assert.Equal(t, wspf.MessageTypeError, rsp.Header.MsgType)

	msgError = &wspf.Error{}
	_ = msgpack.Unmarshal(rsp.Body, msgError)
	assert.Contains(t, *msgError.Error, "unknown protocol: dummy")

	// stop
	msg = &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypePortForward,
			MsgType:   wspf.MessageTypePortForwardStop,
			SessionID: "session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c1",
			},
		},
	}
	w = new(testWriter)
	handler.ServeProtoMsg(msg, w)
	if !assert.Len(t, w.Messages, 1) {
		t.FailNow()
	}
	rsp = w.Messages[0]
	assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
	assert.Equal(t, wspf.MessageTypeError, rsp.Header.MsgType)

	msgError = &wspf.Error{}
	_ = msgpack.Unmarshal(rsp.Body, msgError)
	assert.Equal(t, errPortForwardUnkonwnConnection.Error(), *msgError.Error)

	// forward
	msg = &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypePortForward,
			MsgType:   wspf.MessageTypePortForward,
			SessionID: "session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c1",
			},
		},
	}
	w = new(testWriter)
	handler.ServeProtoMsg(msg, w)
	if !assert.Len(t, w.Messages, 1) {
		t.FailNow()
	}
	rsp = w.Messages[0]
	assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
	assert.Equal(t, wspf.MessageTypeError, rsp.Header.MsgType)

	msgError = &wspf.Error{}
	_ = msgpack.Unmarshal(rsp.Body, msgError)
	assert.Equal(t, errPortForwardUnkonwnConnection.Error(), *msgError.Error)
}

type CloseFunc func() error

func echoTCPServer(t *testing.T) (int, CloseFunc) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var conns []net.Conn
	var workers sync.WaitGroup
	accepted := make(chan struct{})
	go func() {
		defer close(accepted)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conns = append(conns, conn)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				if _, err := io.Copy(conn, conn); err != nil && !errors.Is(err, net.ErrClosed) {
					t.Error(err)
				}
			}()
		}
	}()
	var once sync.Once
	return listener.Addr().(*net.TCPAddr).Port, func() error {
		once.Do(func() {
			_ = listener.Close()
			<-accepted
			for _, conn := range conns {
				_ = conn.Close()
			}
			workers.Wait()
		})
		return nil
	}
}

func TestPortForwardHandlerSuccessfulConnection(t *testing.T) {
	handler := PortForward()()

	tcpPort, closeTCPServer := echoTCPServer(t)
	defer closeTCPServer()
	defer handler.Close()

	// c1: new
	protocol := wspf.PortForwardProtocol(wspf.PortForwardProtocolTCP)
	remoteHost := "localhost"
	remotePort := uint16(tcpPort)
	portForwardNew := &wspf.PortForwardNew{
		Protocol:   &protocol,
		RemoteHost: &remoteHost,
		RemotePort: &remotePort,
	}
	body, _ := msgpack.Marshal(portForwardNew)
	msg := &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypePortForward,
			MsgType:   wspf.MessageTypePortForwardNew,
			SessionID: "session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c1",
			},
		},
		Body: body,
	}
	w := newV3TestWriter()
	handler.ServeProtoMsg(msg, w)

	messages := w.take(t, 1)

	rsp := messages[0]
	assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
	assert.Equal(t, wspf.MessageTypePortForwardNew, rsp.Header.MsgType)
	assert.Nil(t, rsp.Body)

	// c1: forward
	msg = &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypePortForward,
			MsgType:   wspf.MessageTypePortForward,
			SessionID: "session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c1",
			},
		},
		Body: []byte("abcdefghi"),
	}
	handler.ServeProtoMsg(msg, w)

	messages = w.take(t, 2)

	for _, rsp := range messages {
		if rsp.Header.MsgType == wspf.MessageTypePortForwardAck {
			assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
			assert.Equal(t, wspf.MessageTypePortForwardAck, rsp.Header.MsgType)
			assert.Equal(t, "session", rsp.Header.SessionID)
			assert.Equal(t, "c1", rsp.Header.Properties[wspf.PropertyConnectionID].(string))
		} else if rsp.Header.MsgType == wspf.MessageTypePortForward {
			assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
			assert.Equal(t, wspf.MessageTypePortForward, rsp.Header.MsgType)
			assert.Equal(t, "session", rsp.Header.SessionID)
			assert.Equal(t, "c1", rsp.Header.Properties[wspf.PropertyConnectionID].(string))
			assert.Equal(t, []byte("abcdefghi"), rsp.Body)
		}
	}

	msg = &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypePortForward,
			MsgType:   wspf.MessageTypePortForwardAck,
			SessionID: "session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c1",
			},
		},
	}
	handler.ServeProtoMsg(msg, w)

	// c2: new
	protocol = wspf.PortForwardProtocol(wspf.PortForwardProtocolTCP)
	remoteHost = "localhost"
	remotePort = uint16(tcpPort)
	portForwardNew = &wspf.PortForwardNew{
		Protocol:   &protocol,
		RemoteHost: &remoteHost,
		RemotePort: &remotePort,
	}
	body, _ = msgpack.Marshal(portForwardNew)
	msg = &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypePortForward,
			MsgType:   wspf.MessageTypePortForwardNew,
			SessionID: "session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c2",
			},
		},
		Body: body,
	}
	handler.ServeProtoMsg(msg, w)

	messages = w.take(t, 1)

	rsp = messages[0]
	assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
	assert.Equal(t, wspf.MessageTypePortForwardNew, rsp.Header.MsgType)
	assert.Equal(t, "session", rsp.Header.SessionID)
	assert.Equal(t, "c2", rsp.Header.Properties[wspf.PropertyConnectionID].(string))
	assert.Nil(t, rsp.Body)

	// c1: forward, again
	msg = &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypePortForward,
			MsgType:   wspf.MessageTypePortForward,
			SessionID: "session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c1",
			},
		},
		Body: []byte("1234"),
	}
	handler.ServeProtoMsg(msg, w)

	messages = w.take(t, 2)

	for _, rsp := range messages {
		if rsp.Header.MsgType == wspf.MessageTypePortForwardAck {
			assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
			assert.Equal(t, wspf.MessageTypePortForwardAck, rsp.Header.MsgType)
			assert.Equal(t, "session", rsp.Header.SessionID)
			assert.Equal(t, "c1", rsp.Header.Properties[wspf.PropertyConnectionID].(string))
		} else if rsp.Header.MsgType == wspf.MessageTypePortForward {
			assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
			assert.Equal(t, wspf.MessageTypePortForward, rsp.Header.MsgType)
			assert.Equal(t, "session", rsp.Header.SessionID)
			assert.Equal(t, "c1", rsp.Header.Properties[wspf.PropertyConnectionID].(string))
			assert.Equal(t, []byte("1234"), rsp.Body)
		}
	}

	msg = &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypePortForward,
			MsgType:   wspf.MessageTypePortForwardAck,
			SessionID: "session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c1",
			},
		},
	}
	handler.ServeProtoMsg(msg, w)

	// c1: stop
	msg = &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypePortForward,
			MsgType:   wspf.MessageTypePortForwardStop,
			SessionID: "session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c1",
			},
		},
	}
	handler.ServeProtoMsg(msg, w)

	messages = w.take(t, 1)

	rsp = messages[0]
	assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
	assert.Equal(t, wspf.MessageTypePortForwardStop, rsp.Header.MsgType)
	assert.Equal(t, "session", rsp.Header.SessionID)
	assert.Equal(t, "c1", rsp.Header.Properties[wspf.PropertyConnectionID].(string))
	assert.Nil(t, rsp.Body)

	// c2: forward the message with the "stop" payload
	msg = &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypePortForward,
			MsgType:   wspf.MessageTypePortForward,
			SessionID: "session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c2",
			},
		},
		Body: []byte("stop"),
	}
	handler.ServeProtoMsg(msg, w)
	messages = w.take(t, 2)
	assert.NoError(t, closeTCPServer())

	messages = append(messages, w.take(t, 1)...)

	for _, rsp := range messages {
		if rsp.Header.MsgType == wspf.MessageTypePortForwardAck {
			assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
			assert.Equal(t, wspf.MessageTypePortForwardAck, rsp.Header.MsgType)
			assert.Equal(t, "session", rsp.Header.SessionID)
			assert.Equal(t, "c2", rsp.Header.Properties[wspf.PropertyConnectionID].(string))
		} else if rsp.Header.MsgType == wspf.MessageTypePortForward {
			assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
			assert.Equal(t, wspf.MessageTypePortForward, rsp.Header.MsgType)
			assert.Equal(t, "session", rsp.Header.SessionID)
			assert.Equal(t, "c2", rsp.Header.Properties[wspf.PropertyConnectionID].(string))
			assert.Equal(t, []byte("stop"), rsp.Body)
		} else if rsp.Header.MsgType == wspf.MessageTypePortForwardStop {
			assert.Equal(t, ws.ProtoTypePortForward, rsp.Header.Proto)
			assert.Equal(t, wspf.MessageTypePortForwardStop, rsp.Header.MsgType)
			assert.Equal(t, "session", rsp.Header.SessionID)
			assert.Equal(t, "c2", rsp.Header.Properties[wspf.PropertyConnectionID].(string))
			assert.Nil(t, rsp.Body)
		}
	}

	msg = &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     ws.ProtoTypePortForward,
			MsgType:   wspf.MessageTypePortForwardAck,
			SessionID: "session",
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: "c1",
			},
		},
	}
	handler.ServeProtoMsg(msg, w)
}

func portForwardNew(protocol wspf.PortForwardProtocol, host string, port uint16) *wspf.PortForwardNew {
	return &wspf.PortForwardNew{
		Protocol:   &protocol,
		RemoteHost: &host,
		RemotePort: &port,
	}
}

func TestPortForwardHandlerV2(t *testing.T) {
	t.Parallel()
	handler := PortForwardV2()()

	tcpPort, closeTCPServer := echoTCPServer(t)
	defer closeTCPServer()

	w := newV3TestWriter()
	_ = t.Run("new session", func(t *testing.T) {
		body, _ := msgpack.Marshal(portForwardNew(wspf.PortForwardProtocolTCP, "localhost", uint16(tcpPort)))
		handler.ServeProtoMsg(&ws.ProtoMsg{
			Header: ws.ProtoHdr{
				Proto:     ws.ProtoTypePortForwardV2,
				MsgType:   wspf.MessageTypePortForwardNew,
				SessionID: "session",
				Properties: map[string]interface{}{
					wspf.PropertyConnectionID: "c1",
				},
			},
			Body: body,
		}, w)
		messages := w.take(t, 1)
		_ = assert.Len(t, messages, 1) &&
			assert.Equal(t, ws.ProtoTypePortForwardV2, messages[0].Header.Proto) &&
			assert.Equal(t, wspf.MessageTypePortForwardNew, messages[0].Header.MsgType)
		assert.Nil(t, messages[0].Body)
	}) && t.Run("forward message to session", func(t *testing.T) {
		body := []byte("test data")
		handler.ServeProtoMsg(&ws.ProtoMsg{
			Header: ws.ProtoHdr{
				Proto:     ws.ProtoTypePortForwardV2,
				MsgType:   wspf.MessageTypePortForward,
				SessionID: "session",
				Properties: map[string]interface{}{
					wspf.PropertyConnectionID: "c1",
				},
			},
			Body: body,
		}, w)
		messages := w.take(t, 1)
		_ = assert.Len(t, messages, 1) &&
			assert.Equal(t, ws.ProtoTypePortForwardV2, messages[0].Header.Proto) &&
			assert.Equal(t, wspf.MessageTypePortForward, messages[0].Header.MsgType) &&
			assert.Equal(t, []byte("test data"), messages[0].Body)
	}) && t.Run("error/invalid connection ID", func(t *testing.T) {
		body := []byte("test data")
		handler.ServeProtoMsg(&ws.ProtoMsg{
			Header: ws.ProtoHdr{
				Proto:     ws.ProtoTypePortForwardV2,
				MsgType:   wspf.MessageTypePortForward,
				SessionID: "session",
				Properties: map[string]interface{}{
					wspf.PropertyConnectionID: "f2",
				},
			},
			Body: body,
		}, w)
		messages := w.take(t, 1)
		_ = assert.Len(t, messages, 1) &&
			assert.Equal(t, ws.ProtoTypePortForwardV2, messages[0].Header.Proto) &&
			assert.Equal(t, wspf.MessageTypeError, messages[0].Header.MsgType)
	}) && t.Run("close connection sends stop", func(t *testing.T) {
		assert.NoError(t, closeTCPServer(), "error closing connections")
		messages := w.take(t, 1)
		_ = assert.Len(t, messages, 1) &&
			assert.Equal(t, ws.ProtoTypePortForwardV2, messages[0].Header.Proto) &&
			assert.Equal(t, wspf.MessageTypePortForwardStop, messages[0].Header.MsgType)
	})
}
