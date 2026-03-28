// Copyright 2025 Alibaba Group Holding Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package controller

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"

	"github.com/alibaba/opensandbox/execd/pkg/log"
	"github.com/alibaba/opensandbox/execd/pkg/web/model"
)

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  4096,
	WriteBufferSize: 4096,
	// Allow all origins — execd runs behind a trusted reverse proxy.
	CheckOrigin: func(r *http.Request) bool { return true },
}

const (
	wsPingInterval  = 30 * time.Second
	wsReadDeadline  = 60 * time.Second
	wsWriteDeadline = 10 * time.Second
)

// PTYSessionWebSocket handles GET /pty/:sessionId/ws.
//
//  1. Look up session → 404 before upgrade if missing
//  2. Acquire exclusive WS lock → 409 if already held
//  3. Upgrade HTTP → WebSocket
//  4. Start bash if not already running
//  5+6. AtomicAttachOutputWithSnapshot (snapshot + attach under outMu — no loss window)
//  7. defer: detach → pumpWg.Wait → UnlockWS
//  8. Send replay frame if snapshot non-empty
//  9. Send connected frame
//  10. Start RFC 6455 ping, streamPump(s), exitWatcher goroutines
//  11. Read loop: dispatch client frames
func PTYSessionWebSocket(ctx *gin.Context) {
	id := ctx.Param("sessionId")
	if id == "" {
		ctx.JSON(http.StatusBadRequest, model.ErrorResponse{
			Code:    model.ErrorCodeMissingQuery,
			Message: "missing path parameter 'sessionId'",
		})
		return
	}

	// 1. Look up session — must happen before upgrade so we can return HTTP errors.
	session := codeRunner.GetPTYSession(id)
	if session == nil {
		ctx.JSON(http.StatusNotFound, model.ErrorResponse{
			Code:    model.ErrorCodeContextNotFound,
			Message: "pty session " + id + " not found",
		})
		return
	}

	// 2. Acquire exclusive WS lock.
	if !session.LockWS() {
		ctx.JSON(http.StatusConflict, model.ErrorResponse{
			Code:    model.WSErrCodeAlreadyConnected,
			Message: "another client is already connected to pty session " + id,
		})
		return
	}
	// NOTE: the lock is released at the very end of this function (see defer below),
	// only after all pump goroutines have exited.

	// 3. Upgrade HTTP connection to WebSocket.
	conn, err := wsUpgrader.Upgrade(ctx.Writer, ctx.Request, nil)
	if err != nil {
		log.Warning("pty ws upgrade failed for session %s: %v", id, err)
		session.UnlockWS()
		return
	}

	// Resolve query parameters.
	pipeMode := ctx.Query("pty") == "0"
	since := queryInt64(ctx.Query("since"), 0)

	// 4. Start bash if not already running.
	if !session.IsRunning() {
		var startErr error
		if pipeMode {
			startErr = session.StartPipe()
		} else {
			startErr = session.StartPTY()
		}
		if startErr != nil {
			log.Warning("pty start failed for session %s: %v", id, startErr)
			writeErrFrame(conn, model.WSErrCodeStartFailed, startErr.Error())
			_ = conn.Close()
			session.UnlockWS()
			return
		}
	}

	// 5+6. Atomically snapshot replay buffer and attach live pipe — eliminates the
	//      output-loss window where bytes written between ReadFrom and AttachOutput
	//      would be dropped by fanout (stdoutW still nil) yet missed by snapshot.
	stdoutR, stderrR, detach, snapshotBytes, snapshotOffset := session.AttachOutputWithSnapshot(since)

	// 7. Deferred cleanup order: detach writers → wait for pump goroutines → unlock WS.
	var pumpWg sync.WaitGroup
	defer func() {
		detach()
		pumpWg.Wait()
		session.UnlockWS()
	}()

	// cancelCh is closed to signal all goroutines to stop.
	cancelCh := make(chan struct{})
	cancelOnce := sync.OnceFunc(func() { close(cancelCh) })

	// connMu serialises all writes to conn (gorilla/websocket requires single-writer).
	var connMu sync.Mutex

	writeJSON := func(v any) error {
		connMu.Lock()
		defer connMu.Unlock()
		_ = conn.SetWriteDeadline(time.Now().Add(wsWriteDeadline))
		return conn.WriteJSON(v)
	}

	closeConn := func(code int, text string) {
		connMu.Lock()
		_ = conn.SetWriteDeadline(time.Now().Add(wsWriteDeadline))
		_ = conn.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(code, text))
		connMu.Unlock()
		_ = conn.Close()
	}

	// Set initial read deadline; pong handler resets it.
	_ = conn.SetReadDeadline(time.Now().Add(wsReadDeadline))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(wsReadDeadline))
	})

	// 8. Send replay frame if there is missed output.
	if len(snapshotBytes) > 0 {
		frame := make([]byte, 1+8+len(snapshotBytes))
		frame[0] = model.BinReplay
		binary.BigEndian.PutUint64(frame[1:9], uint64(snapshotOffset))
		copy(frame[9:], snapshotBytes)
		// No connMu needed — pump goroutines not yet started.
		_ = conn.SetWriteDeadline(time.Now().Add(wsWriteDeadline))
		if err2 := conn.WriteMessage(websocket.BinaryMessage, frame); err2 != nil {
			log.Warning("pty ws send replay for session %s: %v", id, err2)
			return
		}
	}

	// 9. Send connected frame.
	mode := "pty"
	if !session.IsPTY() {
		mode = "pipe"
	}
	if err2 := writeJSON(model.ServerFrame{
		Type:      "connected",
		SessionID: id,
		Mode:      mode,
	}); err2 != nil {
		log.Warning("pty ws send connected for session %s: %v", id, err2)
		return
	}

	// 10a. RFC 6455 binary ping goroutine (30 s interval).
	go func() {
		t := time.NewTicker(wsPingInterval)
		defer t.Stop()
		for {
			select {
			case <-cancelCh:
				return
			case <-t.C:
				connMu.Lock()
				_ = conn.SetWriteDeadline(time.Now().Add(wsWriteDeadline))
				pingErr := conn.WriteMessage(websocket.PingMessage, nil)
				connMu.Unlock()
				if pingErr != nil {
					cancelOnce()
					return
				}
			}
		}
	}()

	// streamPump reads raw chunks from r and sends them as binary frames over WS.
	streamPump := func(r io.Reader, typeByte byte, name string) {
		defer pumpWg.Done()
		const chunkSize = 32 * 1024
		frame := make([]byte, 1+chunkSize) // single allocation for session lifetime
		frame[0] = typeByte
		for {
			select {
			case <-cancelCh:
				return
			default:
			}
			n, readErr := r.Read(frame[1:])
			if n > 0 {
				connMu.Lock()
				_ = conn.SetWriteDeadline(time.Now().Add(wsWriteDeadline))
				writeErr := conn.WriteMessage(websocket.BinaryMessage, frame[:1+n])
				connMu.Unlock()
				if writeErr != nil {
					log.Warning("pty ws write %s for session %s: %v", name, id, writeErr)
					cancelOnce()
					return
				}
			}
			if readErr != nil {
				// io.EOF or io.ErrClosedPipe when detach() closes the PipeWriter.
				return
			}
		}
	}

	// 10b. Launch stdout pump.
	pumpWg.Add(1)
	go streamPump(stdoutR, model.BinStdout, "stdout")

	// 10c. Launch stderr pump (pipe mode only).
	if stderrR != nil {
		pumpWg.Add(1)
		go streamPump(stderrR, model.BinStderr, "stderr")
	}

	// 10d. Exit watcher: waits for the process to exit, then sends exit frame
	// and closes the WS connection immediately (unblocks ReadJSON in the read loop).
	go func() {
		doneCh := session.Done()
		if doneCh == nil {
			return
		}
		select {
		case <-doneCh:
		case <-cancelCh:
			return
		}
		exitCode := session.ExitCode()
		_ = writeJSON(model.ServerFrame{
			Type:     "exit",
			ExitCode: &exitCode,
		})
		closeConn(websocket.CloseNormalClosure, "process exited")
		cancelOnce()
	}()

	// 11. Client read loop.
	for {
		select {
		case <-cancelCh:
			return
		default:
		}

		msgType, data, err2 := conn.ReadMessage()
		if err2 != nil {
			cancelOnce()
			return
		}

		// Any incoming frame resets the read deadline.
		_ = conn.SetReadDeadline(time.Now().Add(wsReadDeadline))

		switch msgType {

		case websocket.BinaryMessage:
			if len(data) == 0 {
				continue
			}
			if data[0] != model.BinStdin {
				continue // only stdin expected C→S
			}
			if _, writeErr := session.WriteStdin(data[1:]); writeErr != nil {
				_ = writeJSON(model.ServerFrame{Type: "error", Code: model.WSErrCodeStdinWriteFailed,
					Error: writeErr.Error()})
				cancelOnce()
				return
			}

		case websocket.TextMessage:
			var frame model.ClientFrame
			if json.Unmarshal(data, &frame) != nil {
				continue
			}
			switch frame.Type {
			case "stdin":
				// wscat / debug fallback: plain UTF-8 text, no base64.
				if _, writeErr := session.WriteStdin([]byte(frame.Data)); writeErr != nil {
					_ = writeJSON(model.ServerFrame{Type: "error", Code: model.WSErrCodeStdinWriteFailed,
						Error: writeErr.Error()})
					cancelOnce()
					return
				}
			case "signal":
				session.SendSignal(frame.Signal)
			case "resize":
				if frame.Cols > 0 && frame.Rows > 0 {
					if resErr := session.ResizePTY(uint16(frame.Cols), uint16(frame.Rows)); resErr != nil {
						log.Warning("pty resize session %s: %v", id, resErr)
					}
				}
			case "ping":
				_ = writeJSON(model.ServerFrame{Type: "pong"})
			default:
				_ = writeJSON(model.ServerFrame{Type: "error", Code: model.WSErrCodeInvalidFrame,
					Error: fmt.Sprintf("unknown frame type %q", frame.Type)})
			}
		}
	}
}

// writeErrFrame sends a JSON error frame. Safe to call before pump goroutines start.
func writeErrFrame(conn *websocket.Conn, code, message string) {
	_ = conn.SetWriteDeadline(time.Now().Add(wsWriteDeadline))
	_ = conn.WriteJSON(model.ServerFrame{
		Type:  "error",
		Error: message,
		Code:  code,
	})
}

// queryInt64 parses a decimal query string value, returning defaultVal on error.
func queryInt64(s string, defaultVal int64) int64 {
	if s == "" {
		return defaultVal
	}
	var n int64
	if _, err := fmt.Sscanf(s, "%d", &n); err != nil {
		return defaultVal
	}
	return n
}
