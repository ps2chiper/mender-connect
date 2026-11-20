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
	"bytes"
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
	portForwardV3DefaultFrame    = 7680
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
	udpBatch       bool
	ctx            context.Context
	ctxCancel      context.CancelFunc
	portForwarders map[string]*MenderPortForwarder
	mapMutex       *sync.Mutex
	credits        chan struct{}

	closeMu          sync.Mutex
	closed           bool
	targetReadClosed bool
	clientReadClosed bool
}

func (f *MenderPortForwarder) Connect(protocol string, host string, portNumber uint16) error {
	if err := f.dial(protocol, host, portNumber); err != nil {
		return err
	}
	go f.Read()
	return nil
}

func (f *MenderPortForwarder) dial(protocol string, host string, portNumber uint16) error {
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
	window := 0
	switch f.proto {
	case ws.ProtoTypePortForward:
		window = 1
	case ProtoTypePortForwardV3:
		window = portForwardV3Window
	}
	if window > 0 {
		f.credits = make(chan struct{}, window)
		for i := 0; i < window; i++ {
			f.credits <- struct{}{}
		}
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	f.ctx = ctx
	f.ctxCancel = cancelFunc

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
		if f.portForwarders[f.ConnectionID] == f {
			delete(f.portForwarders, f.ConnectionID)
		}
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
	// The read loop calls this once. Publish EOF before allowing the peer's
	// half-close to retire this connection.
	if err := f.writeHalfClose(); err != nil {
		log.Errorf("port-forward[%s/%s] half-close: %v", f.SessionID, f.ConnectionID, err)
		_ = f.Close(true)
		return
	}
	f.closeMu.Lock()
	f.targetReadClosed = true
	bothClosed := f.clientReadClosed
	f.closeMu.Unlock()
	if bothClosed {
		_ = f.Close(false)
	}
}

// ClientHalfClose handles the peer's half_close: stop writing to the target,
// leaving the target's read side alive so its response can still be delivered.
func (f *MenderPortForwarder) ClientHalfClose() error {
	f.closeMu.Lock()
	if f.closed || f.clientReadClosed {
		f.closeMu.Unlock()
		return nil
	}
	tcpConn, ok := f.conn.(*net.TCPConn)
	if !ok {
		f.closeMu.Unlock()
		return errors.New("half-close requires a TCP connection")
	}
	err := tcpConn.CloseWrite()
	f.clientReadClosed = err == nil
	bothClosed := f.targetReadClosed
	f.closeMu.Unlock()
	if err != nil || bothClosed {
		_ = f.Close(false)
	}
	return err
}

// waitCredit uses the same idle deadline as the socket. Closing a flow also
// wakes a sender stalled behind an unacknowledged window.
func (f *MenderPortForwarder) waitCredit(deadline time.Time) bool {
	if f.credits == nil {
		return true
	}
	select {
	case <-f.credits:
		return true
	default:
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-f.credits:
		return true
	case <-timer.C:
	case <-f.ctx.Done():
	}
	return false
}

func (f *MenderPortForwarder) Read() {
	buf := make([]byte, f.frameSize)
	for f.ctx.Err() == nil {
		deadline := time.Now().Add(portForwardConnectionTimeout)
		if err := f.conn.SetReadDeadline(deadline); err != nil {
			_ = f.Close(true)
			return
		}
		n, readErr := f.conn.Read(buf)
		if n > 0 {
			if !f.waitCredit(deadline) {
				_ = f.Close(true)
				return
			}
			m := &ws.ProtoMsg{
				Header: ws.ProtoHdr{
					Proto:      f.proto,
					MsgType:    wspf.MessageTypePortForward,
					SessionID:  f.SessionID,
					Properties: map[string]interface{}{wspf.PropertyConnectionID: f.ConnectionID},
				},
				Body: bytes.Clone(buf[:n]),
			}
			if err := f.ResponseWriter.WriteProtoMsg(m); err != nil {
				log.Errorf("port-forward[%s/%s] send: %v", f.SessionID, f.ConnectionID, err)
				_ = f.Close(true)
				return
			}
		}
		if readErr != nil {
			if f.ctx.Err() != nil {
				return
			}
			if f.proto == ProtoTypePortForwardV3 && readErr == io.EOF {
				f.targetReadEOF()
			} else {
				_ = f.Close(true)
			}
			return
		}
	}
}

// readDatagrams flushes a sparse batch on time and a busy batch on size.
func (f *MenderPortForwarder) readDatagrams() {
	defer f.Close(true)
	packet := make([]byte, udpMaxDatagram+1)
	for f.ctx.Err() == nil {
		deadline := time.Now().Add(portForwardConnectionTimeout)
		if f.conn.SetReadDeadline(deadline) != nil {
			return
		}
		var body []byte
		var started time.Time
		for count := 0; count < udpBatchCount && len(body)+udpMaxDatagram+2 <= udpBatchFrame; count++ {
			n, err := f.conn.Read(packet)
			if err != nil {
				if e, ok := err.(net.Error); ok && e.Timeout() && len(body) > 0 {
					break
				}
				return
			}
			if n > udpMaxDatagram {
				return
			}
			body = appendDatagram(body, packet[:n])
			if count == 0 {
				started = time.Now()
				if f.conn.SetReadDeadline(started.Add(udpBatchDelay)) != nil {
					return
				}
			}
		}
		body = finishBatch(body, started)
		if !f.waitCredit(deadline) {
			return
		}
		msg := &ws.ProtoMsg{Header: ws.ProtoHdr{Proto: f.proto, MsgType: wspf.MessageTypePortForward, SessionID: f.SessionID, Properties: map[string]interface{}{wspf.PropertyConnectionID: f.ConnectionID}}, Body: body}
		if err := f.ResponseWriter.WriteProtoMsg(msg); err != nil {
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
	closed         bool
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

func (h *PortForwardHandler) Close() error {
	h.mutex.Lock()
	h.closed = true
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
		if id, ok := msg.Header.Properties[wspf.PropertyConnectionID].(string); ok {
			response.Header.Properties = map[string]interface{}{wspf.PropertyConnectionID: id}
		}
		if err := w.WriteProtoMsg(response); err != nil {
			log.Errorf("portForwardHandler: webSock.WriteMessage(%+v)", err)
		}
	}
}

type portForwardNewV3 struct {
	UDPBatch        bool                      `msgpack:"udp_batch_v1,omitempty"`
	RemoteHost      *string                   `msgpack:"remote_host"`
	RemotePort      *uint16                   `msgpack:"remote_port"`
	Protocol        *wspf.PortForwardProtocol `msgpack:"protocol"`
	FlowControl     bool                      `msgpack:"flow_control,omitempty"`
	TCPFrameSize    uint32                    `msgpack:"tcp_frame_size,omitempty"`
	TCPMaxFrameSize uint32                    `msgpack:"tcp_max_frame_size,omitempty"`
}

func v3FrameSize(req *portForwardNewV3) int {
	size := req.TCPMaxFrameSize
	if size == 0 {
		size = req.TCPFrameSize
	}
	if size == 0 {
		return portForwardV3DefaultFrame
	}
	return int(min(size, uint32(portForwardV3MaxFrameSize)))
}

func (h *PortForwardHandler) portForwardHandlerNew(message *ws.ProtoMsg, w ResponseWriter) error {
	var protocol *wspf.PortForwardProtocol
	var host *string
	var portNumber *uint16
	frameSize := portForwardBuffSize
	udpBatch := false

	if h.proto == ProtoTypePortForwardV3 {
		req := &portForwardNewV3{}
		if err := msgpack.Unmarshal(message.Body, req); err != nil {
			return err
		}
		protocol = req.Protocol
		host = req.RemoteHost
		portNumber = req.RemotePort
		frameSize = v3FrameSize(req)
		udpBatch = req.UDPBatch && req.FlowControl && protocol != nil && string(*protocol) == wspf.PortForwardProtocolUDP
		if udpBatch {
			frameSize = udpBatchFrame
		}
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
		udpBatch:       udpBatch,
		portForwarders: h.portForwarders,
		mapMutex:       &h.mutex,
	}

	log.Infof(
		"port-forward: new %s/%s: %s/%s:%d",
		message.Header.SessionID,
		connectionID,
		*protocol,
		*host,
		*portNumber,
	)
	if h.get(connectionID) != nil {
		return errors.New("connection already exists")
	}
	if h.proto == ProtoTypePortForwardV3 && string(*protocol) != wspf.PortForwardProtocolTCP && !udpBatch {
		return errors.New("v3 UDP requires negotiated batching and flow control")
	}
	err := portForwarder.dial(string(*protocol), *host, *portNumber)
	if err != nil {
		return err
	}

	h.mutex.Lock()
	if h.closed || h.portForwarders[connectionID] != nil {
		h.mutex.Unlock()
		_ = portForwarder.Close(false)
		return errors.New("session closed or connection already exists")
	}
	h.portForwarders[connectionID] = portForwarder
	h.mutex.Unlock()

	var responseBody []byte
	if udpBatch {
		responseBody, _ = msgpack.Marshal(map[string]bool{"udp_batch_v1": true})
	} else if h.proto == ProtoTypePortForwardV3 {
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
		_ = portForwarder.Close(false)
		return err
	}
	if udpBatch {
		sock := portForwarder.conn.(*net.UDPConn)
		_ = sock.SetReadBuffer(4 * 1024 * 1024)
		_ = sock.SetWriteBuffer(4 * 1024 * 1024)
		go portForwarder.readDatagrams()
	} else {
		go portForwarder.Read()
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

	if h.proto == ProtoTypePortForwardV3 && len(message.Body) > portForwarder.frameSize {
		return errors.New("frame exceeds negotiated TCP frame size")
	}

	if portForwarder.udpBatch {
		packets, err := splitDatagrams(message.Body)
		if err != nil {
			return err
		}
		start := time.Now()
		for i, pkt := range packets {
			paceGroup(start, message.Body, i, len(packets))
			if n, err := portForwarder.conn.Write(pkt); err != nil {
				return err
			} else if n != len(pkt) {
				return io.ErrShortWrite
			}
		}
	} else if err := portForwarder.Write(message.Body); err != nil {
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
		// A batched ACK can arrive after both TCP halves have closed.
		if h.proto == ProtoTypePortForwardV3 && connectionID != "" {
			return nil
		}
		return errPortForwardUnkonwnConnection
	}

	count := uint32(1)
	if h.proto == ProtoTypePortForwardV3 && len(message.Body) != 0 {
		if len(message.Body) != 4 {
			return errors.New("invalid v3 ACK length")
		}
		count = min(binary.BigEndian.Uint32(message.Body), uint32(portForwardV3Window))
	}
	for i := uint32(0); i < count; i++ {
		select {
		case portForwarder.credits <- struct{}{}:
		default:
			return nil
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
