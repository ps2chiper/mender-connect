// Copyright 2021 Northern.tech AS
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
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/mendersoftware/go-lib-micro/ws"
	wspf "github.com/mendersoftware/go-lib-micro/ws/portforward"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	portForwardBuffSize          = 4096
	portForwardV3FrameSize       = 256 * 1024
	portForwardV3MaxFrameSize    = 256 * 1024
	portForwardV3Window          = 16
	portForwardConnectionTimeout = time.Second * 600

	// ProtoTypePortForwardV3 is the opt-in, flow-controlled successor to v2.
	ProtoTypePortForwardV3 ws.ProtoType = ws.ProtoTypePortForwardV2 + 0x100

	messageTypePortForwardHalfClose = "half_close"
)

var (
	errPortForwardInvalidMessage = errors.New(
		"invalid port-forward message: missing connection_id, remote_port or protocol",
	)
	errPortForwardUnkonwnMessageType = errors.New("unknown message type")
	errPortForwardUnkonwnConnection  = errors.New("unknown connection")
)

type MenderPortForwarder struct {
	proto          ws.ProtoType
	SessionID      string
	ConnectionID   string
	ResponseWriter ResponseWriter
	conn           net.Conn
	frameSize      int
	ctx            context.Context
	ctxCancel      context.CancelFunc
	mutexAck       *sync.Mutex
	portForwarders map[string]*MenderPortForwarder
	mapMutex       *sync.Mutex
	credits        chan struct{}

	closeMu          sync.Mutex
	closed           bool
	targetReadClosed bool
	clientReadClosed bool
}

func (f *MenderPortForwarder) Connect(protocol string, host string, portNumber uint16) error {
	log.Debugf(
		"port-forward[%s/%s] connect: %s/%s:%d",
		f.SessionID,
		f.ConnectionID,
		protocol,
		host,
		portNumber,
	)

	if protocol == wspf.PortForwardProtocolTCP || protocol == wspf.PortForwardProtocolUDP {
		conn, err := net.Dial(protocol, host+":"+strconv.Itoa(int(portNumber)))
		if err != nil {
			return err
		}
		f.conn = conn
	} else {
		return errors.New("unknown protocol: " + protocol)
	}

	if f.frameSize <= 0 {
		f.frameSize = portForwardBuffSize
	}
	if f.proto == ProtoTypePortForwardV3 {
		f.credits = make(chan struct{}, portForwardV3Window)
		for i := 0; i < portForwardV3Window; i++ {
			f.credits <- struct{}{}
		}
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	f.ctx = ctx
	f.ctxCancel = cancelFunc

	go f.Read()

	return nil
}

func (f *MenderPortForwarder) writeStop() {
	m := &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     f.proto,
			MsgType:   wspf.MessageTypePortForwardStop,
			SessionID: f.SessionID,
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: f.ConnectionID,
			},
		},
	}
	if err := f.ResponseWriter.WriteProtoMsg(m); err != nil {
		log.Errorf("portForwardHandler: webSock.WriteMessage(%+v)", err)
	}
}

func (f *MenderPortForwarder) writeHalfClose() error {
	m := &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     f.proto,
			MsgType:   messageTypePortForwardHalfClose,
			SessionID: f.SessionID,
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: f.ConnectionID,
			},
		},
	}
	return f.ResponseWriter.WriteProtoMsg(m)
}

func (f *MenderPortForwarder) Close(sendStopMessage bool) error {
	f.closeMu.Lock()
	if f.closed {
		f.closeMu.Unlock()
		return nil
	}
	f.closed = true
	conn := f.conn
	cancel := f.ctxCancel
	mapMutex := f.mapMutex
	f.closeMu.Unlock()

	log.Debugf("port-forward[%s/%s] close", f.SessionID, f.ConnectionID)
	if sendStopMessage {
		f.writeStop()
	}
	if cancel != nil {
		cancel()
	}
	if mapMutex != nil {
		mapMutex.Lock()
		delete(f.portForwarders, f.ConnectionID)
		mapMutex.Unlock()
	}
	if conn == nil {
		return nil
	}
	return conn.Close()
}

// targetReadEOF handles EOF on the target's read side. For v3 this is a
// half-close: the target can no longer send data, but the peer may still send
// data to the target. Earlier protocols retain their full-close behaviour.
func (f *MenderPortForwarder) targetReadEOF() {
	f.closeMu.Lock()
	if f.closed {
		f.closeMu.Unlock()
		return
	}
	alreadyClosed := f.targetReadClosed
	f.targetReadClosed = true
	bothClosed := f.clientReadClosed
	f.closeMu.Unlock()

	if !alreadyClosed {
		if err := f.writeHalfClose(); err != nil {
			log.Errorf("portForwardHandler: half-close: %s", err.Error())
		}
	}
	if bothClosed {
		_ = f.Close(false)
	}
}

// ClientHalfClose handles the peer's half_close: stop writing to the target,
// leaving the target's read side alive so its response can still be delivered.
func (f *MenderPortForwarder) ClientHalfClose() error {
	f.closeMu.Lock()
	if f.closed {
		f.closeMu.Unlock()
		return nil
	}
	if f.clientReadClosed {
		f.closeMu.Unlock()
		return nil
	}
	f.clientReadClosed = true
	bothClosed := f.targetReadClosed
	f.closeMu.Unlock()

	var err error
	if tcpConn, ok := f.conn.(*net.TCPConn); ok {
		err = tcpConn.CloseWrite()
	} else {
		err = errors.New("half-close requires a TCP connection")
	}
	if bothClosed {
		_ = f.Close(false)
	}
	return err
}

func (f *MenderPortForwarder) Read() {
	errChan := make(chan error, 1)
	dataChan := make(chan []byte)

	go func() {
		data := make([]byte, f.frameSize)

		for {
			n, err := f.conn.Read(data)
			if err != nil {
				select {
				case errChan <- err:
				case <-f.ctx.Done():
				}
				break
			}
			if n > 0 {
				tmp := make([]byte, n)
				copy(tmp, data[:n])
				select {
				case dataChan <- tmp:
				case <-f.ctx.Done():
					return
				}
			}
		}
	}()

	for {
		select {
		case err := <-errChan:
			if f.proto == ProtoTypePortForwardV3 && err == io.EOF {
				f.targetReadEOF()
				return
			}
			if err != io.EOF {
				log.Errorf(
					"port-forward[%s/%s] error: %v\n",
					f.SessionID,
					f.ConnectionID,
					err.Error(),
				)
			}
			_ = f.Close(true)
			return
		case data := <-dataChan:
			log.Debugf("port-forward[%s/%s] read %d bytes", f.SessionID, f.ConnectionID, len(data))

			if f.proto == ProtoTypePortForwardV3 {
				select {
				case <-f.credits:
				case <-f.ctx.Done():
					return
				}
			}

			if f.proto == ws.ProtoTypePortForward {
				// Lock the ack mutex: v1 allows only one in-flight message.
				f.mutexAck.Lock()
			}

			m := &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:     f.proto,
					MsgType:   wspf.MessageTypePortForward,
					SessionID: f.SessionID,
					Properties: map[string]interface{}{
						wspf.PropertyConnectionID: f.ConnectionID,
					},
				},
				Body: data,
			}
			if err := f.ResponseWriter.WriteProtoMsg(m); err != nil {
				log.Errorf("portForwardHandler: webSock.WriteMessage(%+v)", err)
			}
		case <-time.After(portForwardConnectionTimeout):
			_ = f.Close(true)
			return
		case <-f.ctx.Done():
			return
		}
	}
}

func (f *MenderPortForwarder) Write(body []byte) error {
	log.Debugf("port-forward[%s/%s] write %d bytes", f.SessionID, f.ConnectionID, len(body))
	for {
		n, err := f.conn.Write(body)
		if err != nil {
			return err
		}
		body = body[n:]
		if len(body) <= 0 {
			break
		}
	}
	return nil
}

type PortForwardHandler struct {
	portForwarders map[string]*MenderPortForwarder
	proto          ws.ProtoType
	mutex          sync.Mutex
}

func PortForward() Constructor {
	return func() SessionHandler {
		return &PortForwardHandler{
			portForwarders: make(map[string]*MenderPortForwarder),
			proto:          ws.ProtoTypePortForward,
		}
	}
}

func PortForwardV2() Constructor {
	return func() SessionHandler {
		return &PortForwardHandler{
			portForwarders: make(map[string]*MenderPortForwarder),
			proto:          ws.ProtoTypePortForwardV2,
		}
	}
}

func PortForwardV3() Constructor {
	return func() SessionHandler {
		return &PortForwardHandler{
			portForwarders: make(map[string]*MenderPortForwarder),
			proto:          ProtoTypePortForwardV3,
		}
	}
}

func (h *PortForwardHandler) get(connectionID string) *MenderPortForwarder {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return h.portForwarders[connectionID]
}

func (h *PortForwardHandler) remove(connectionID string) {
	h.mutex.Lock()
	delete(h.portForwarders, connectionID)
	h.mutex.Unlock()
}

func (h *PortForwardHandler) Close() error {
	h.mutex.Lock()
	portForwarders := make([]*MenderPortForwarder, 0, len(h.portForwarders))
	for _, f := range h.portForwarders {
		portForwarders = append(portForwarders, f)
	}
	h.mutex.Unlock()

	var errs Errors
	for _, f := range portForwarders {
		if err := f.Close(false); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errs
	}
	return nil
}

func (h *PortForwardHandler) ServeProtoMsg(msg *ws.ProtoMsg, w ResponseWriter) {
	var err error
	if msg.Header.Proto == h.proto {
		switch msg.Header.MsgType {
		case wspf.MessageTypePortForwardNew:
			err = h.portForwardHandlerNew(msg, w)
		case wspf.MessageTypePortForwardStop:
			err = h.portForwardHandlerStop(msg, w)
		case wspf.MessageTypePortForward:
			err = h.portForwardHandlerForward(msg, w)
		case wspf.MessageTypePortForwardAck:
			if h.proto == ws.ProtoTypePortForward || h.proto == ProtoTypePortForwardV3 {
				err = h.portForwardHandlerAck(msg, w)
				break
			}
			fallthrough // For v2 this is an unknown message type
		case messageTypePortForwardHalfClose:
			if h.proto == ProtoTypePortForwardV3 {
				err = h.portForwardHandlerHalfClose(msg, w)
				break
			}
			fallthrough
		default:
			err = errPortForwardUnkonwnMessageType
		}
	} else {
		err = fmt.Errorf("invalid protocol ID %d in request header", msg.Header.Proto)
	}
	if err != nil {
		log.Errorf("portForwardHandler(%+v)", err)

		errMessage := err.Error()
		body, err := msgpack.Marshal(&wspf.Error{
			Error:       &errMessage,
			MessageType: &msg.Header.MsgType,
		})
		if err != nil {
			log.Errorf("portForwardHandler: msgpack.Marshal(%+v)", err)
		}
		response := &ws.ProtoMsg{
			Header: ws.ProtoHdr{
				Proto:     h.proto,
				MsgType:   wspf.MessageTypeError,
				SessionID: msg.Header.SessionID,
			},
			Body: body,
		}
		if err := w.WriteProtoMsg(response); err != nil {
			log.Errorf("portForwardHandler: webSock.WriteMessage(%+v)", err)
		}
	}
}

type portForwardNewV3 struct {
	RemoteHost      *string                   `msgpack:"remote_host"`
	RemotePort      *uint16                   `msgpack:"remote_port"`
	Protocol        *wspf.PortForwardProtocol `msgpack:"protocol"`
	FlowControl     bool                      `msgpack:"flow_control,omitempty"`
	TCPFrameSize    uint32                    `msgpack:"tcp_frame_size,omitempty"`
	TCPMaxFrameSize uint32                    `msgpack:"tcp_max_frame_size,omitempty"`
}

func v3FrameSize(req *portForwardNewV3) int {
	if req.TCPMaxFrameSize >= portForwardV3MaxFrameSize ||
		req.TCPFrameSize >= portForwardV3MaxFrameSize {
		return portForwardV3FrameSize
	}
	if req.TCPFrameSize > 0 {
		frameSize := int(req.TCPFrameSize)
		if frameSize > portForwardV3MaxFrameSize {
			frameSize = portForwardV3MaxFrameSize
		}
		if frameSize < portForwardBuffSize {
			frameSize = portForwardBuffSize
		}
		return frameSize
	}
	return portForwardBuffSize
}

func (h *PortForwardHandler) portForwardHandlerNew(message *ws.ProtoMsg, w ResponseWriter) error {
	var protocol *wspf.PortForwardProtocol
	var host *string
	var portNumber *uint16
	frameSize := portForwardBuffSize

	if h.proto == ProtoTypePortForwardV3 {
		req := &portForwardNewV3{}
		if err := msgpack.Unmarshal(message.Body, req); err != nil {
			return err
		}
		protocol = req.Protocol
		host = req.RemoteHost
		portNumber = req.RemotePort
		frameSize = v3FrameSize(req)
	} else {
		req := &wspf.PortForwardNew{}
		if err := msgpack.Unmarshal(message.Body, req); err != nil {
			return err
		}
		protocol = req.Protocol
		host = req.RemoteHost
		portNumber = req.RemotePort
	}

	connectionID, _ := message.Header.Properties[wspf.PropertyConnectionID].(string)

	if protocol == nil || *protocol == "" || host == nil || *host == "" || portNumber == nil ||
		*portNumber == 0 ||
		connectionID == "" {
		return errPortForwardInvalidMessage
	}

	portForwarder := &MenderPortForwarder{
		proto:          h.proto,
		SessionID:      message.Header.SessionID,
		ConnectionID:   connectionID,
		ResponseWriter: w,
		frameSize:      frameSize,
		mutexAck:       &sync.Mutex{},
		portForwarders: h.portForwarders,
		mapMutex:       &h.mutex,
	}

	h.mutex.Lock()
	h.portForwarders[connectionID] = portForwarder
	h.mutex.Unlock()

	log.Infof(
		"port-forward: new %s/%s: %s/%s:%d",
		message.Header.SessionID,
		connectionID,
		*protocol,
		*host,
		*portNumber,
	)
	err := portForwarder.Connect(string(*protocol), *host, *portNumber)
	if err != nil {
		h.remove(connectionID)
		return err
	}

	var responseBody []byte
	if h.proto == ProtoTypePortForwardV3 {
		responseBody, _ = msgpack.Marshal(&struct {
			TCPFrameSize uint32 `msgpack:"tcp_frame_size"`
		}{
			TCPFrameSize: uint32(frameSize),
		})
	}

	response := &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     message.Header.Proto,
			MsgType:   message.Header.MsgType,
			SessionID: message.Header.SessionID,
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: connectionID,
			},
		},
		Body: responseBody,
	}
	if err := w.WriteProtoMsg(response); err != nil {
		log.Errorf("portForwardHandler: webSock.WriteMessage(%+v)", err)
	}

	return nil
}

func (h *PortForwardHandler) portForwardHandlerStop(message *ws.ProtoMsg, w ResponseWriter) error {
	connectionID, _ := message.Header.Properties[wspf.PropertyConnectionID].(string)
	portForwarder := h.get(connectionID)
	if portForwarder == nil {
		return errPortForwardUnkonwnConnection
	}

	log.Infof("port-forward: stop %s/%s", message.Header.SessionID, connectionID)
	h.remove(connectionID)
	if err := portForwarder.Close(false); err != nil {
		return err
	}

	response := &ws.ProtoMsg{
		Header: ws.ProtoHdr{
			Proto:     message.Header.Proto,
			MsgType:   message.Header.MsgType,
			SessionID: message.Header.SessionID,
			Properties: map[string]interface{}{
				wspf.PropertyConnectionID: connectionID,
			},
		},
	}
	if err := w.WriteProtoMsg(response); err != nil {
		log.Warnf("portForwardHandler: error writing ack message: %s", err.Error())
	}

	return nil
}

func (h *PortForwardHandler) portForwardHandlerForward(
	message *ws.ProtoMsg,
	w ResponseWriter,
) error {
	connectionID, _ := message.Header.Properties[wspf.PropertyConnectionID].(string)
	portForwarder := h.get(connectionID)
	if portForwarder == nil {
		return errPortForwardUnkonwnConnection
	}

	if err := portForwarder.Write(message.Body); err != nil {
		return fmt.Errorf("error forwarding message to connection: %w", err)
	}

	switch h.proto {
	case ws.ProtoTypePortForward:
		// v1 sends a single empty ACK per frame.
		return w.WriteProtoMsg(&ws.ProtoMsg{
			Header: ws.ProtoHdr{
				Proto:     message.Header.Proto,
				MsgType:   wspf.MessageTypePortForwardAck,
				SessionID: message.Header.SessionID,
				Properties: map[string]interface{}{
					wspf.PropertyConnectionID: connectionID,
				},
			},
		})
	case ProtoTypePortForwardV3:
		// v3 ACKs carry the number of released input credits. The daemon
		// accepts one frame at a time, so release exactly one credit.
		body := make([]byte, 4)
		binary.BigEndian.PutUint32(body, 1)
		return w.WriteProtoMsg(&ws.ProtoMsg{
			Header: ws.ProtoHdr{
				Proto:     message.Header.Proto,
				MsgType:   wspf.MessageTypePortForwardAck,
				SessionID: message.Header.SessionID,
				Properties: map[string]interface{}{
					wspf.PropertyConnectionID: connectionID,
				},
			},
			Body: body,
		})
	default:
		return nil
	}
}

func (h *PortForwardHandler) portForwardHandlerAck(message *ws.ProtoMsg, w ResponseWriter) error {
	connectionID, _ := message.Header.Properties[wspf.PropertyConnectionID].(string)
	portForwarder := h.get(connectionID)
	if portForwarder == nil {
		return errPortForwardUnkonwnConnection
	}

	if h.proto == ws.ProtoTypePortForward {
		// Unlock the ack mutex, do not panic if it is not locked.
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("portForwardHandlerAck: recover(%+v)", r)
			}
		}()
		portForwarder.mutexAck.Unlock()
		return nil
	}
	if h.proto == ProtoTypePortForwardV3 {
		count := 1
		if len(message.Body) >= 4 {
			count = int(binary.BigEndian.Uint32(message.Body[:4]))
			if count > portForwardV3Window {
				count = portForwardV3Window
			}
		}
		for i := 0; i < count; i++ {
			select {
			case portForwarder.credits <- struct{}{}:
			default:
			}
		}
	}
	return nil
}

func (h *PortForwardHandler) portForwardHandlerHalfClose(message *ws.ProtoMsg, w ResponseWriter) error {
	connectionID, _ := message.Header.Properties[wspf.PropertyConnectionID].(string)
	portForwarder := h.get(connectionID)
	if portForwarder == nil {
		return errPortForwardUnkonwnConnection
	}
	return portForwarder.ClientHalfClose()
}
