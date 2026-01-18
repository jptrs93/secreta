package secreta

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"time"
)

var SocketPath = "/tmp/secreta.sock"
var SocketTimeout = 45 * time.Second

type ErrorEnvelope struct {
	Code      string            `json:"code"`
	Message   string            `json:"message"`
	Retryable bool              `json:"retryable"`
	Details   map[string]string `json:"details,omitempty"`
}

type RequestEnvelope struct {
	RequestID string `json:"requestId"`
	Method    string `json:"method"`
	Params    string `json:"params"`
}

type ResponseEnvelope struct {
	RequestID string         `json:"requestId"`
	Result    string         `json:"result"`
	Error     *ErrorEnvelope `json:"error"`
}

type SecretCreateRequest struct {
	Name         string            `json:"name"`
	SecretValue  string            `json:"secretValue"`
	CacheSeconds *int              `json:"cacheSeconds,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type SecretCreateResponse struct {
	SecretID     string `json:"secretId"`
	StoredName   string `json:"storedName"`
	CacheSeconds int    `json:"cacheSeconds"`
}

type SecretAccessRequest struct {
	Name   string `json:"name"`
	Reason string `json:"reason,omitempty"`
}

type SecretAccessResponse struct {
	SecretValue   string `json:"secretValue"`
	CacheSeconds  int    `json:"cacheSeconds"`
	AuthRequired  bool   `json:"authRequired"`
	AuthSatisfied bool   `json:"authSatisfied"`
}

type FileReadRequest struct {
	Path   string `json:"path"`
	Reason string `json:"reason,omitempty"`
}

type FileReadResponse struct {
	Plaintext string `json:"plaintext"`
}

func CreateSecret(name string, value string, cacheSeconds *int, metadata map[string]string) (*SecretCreateResponse, error) {
	request := SecretCreateRequest{
		Name:         name,
		SecretValue:  value,
		CacheSeconds: cacheSeconds,
		Metadata:     metadata,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	response, err := sendRequest("secret.create", payload)
	if err != nil {
		return nil, err
	}
	var result SecretCreateResponse
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func FetchSecret(name string, reason string) (*SecretAccessResponse, error) {
	request := SecretAccessRequest{
		Name:   name,
		Reason: reason,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	response, err := sendRequest("secret.access", payload)
	if err != nil {
		return nil, err
	}
	var result SecretAccessResponse
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func ReadFile(path string, reason string) (*FileReadResponse, error) {
	resolved := path
	if !filepath.IsAbs(path) {
		if abs, err := filepath.Abs(path); err == nil {
			resolved = abs
		}
	}
	request := FileReadRequest{
		Path:   resolved,
		Reason: reason,
	}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	response, err := sendRequest("file.read", payload)
	if err != nil {
		return nil, err
	}
	var result FileReadResponse
	if err := json.Unmarshal(response, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

func sendRequest(method string, params []byte) ([]byte, error) {
	if SocketPath == "" {
		SocketPath = "/tmp/secreta.sock"
	}

	requestID, err := newRequestID()
	if err != nil {
		return nil, err
	}

	envelope := RequestEnvelope{
		RequestID: requestID,
		Method:    method,
		Params:    base64.StdEncoding.EncodeToString(params),
	}

	payload, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}

	framed := frame(payload)

	conn, err := net.DialTimeout("unix", SocketPath, SocketTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(SocketTimeout)); err != nil {
		return nil, err
	}

	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}

	response, err := readFrame(conn)
	if err != nil {
		return nil, err
	}

	var envelopeResponse ResponseEnvelope
	if err := json.Unmarshal(response, &envelopeResponse); err != nil {
		return nil, err
	}

	if envelopeResponse.Error != nil {
		return nil, fmt.Errorf("secreta error (%s): %s", envelopeResponse.Error.Code, envelopeResponse.Error.Message)
	}

	if len(envelopeResponse.Result) == 0 {
		return nil, fmt.Errorf("secreta error: empty response")
	}

	decoded, err := base64.StdEncoding.DecodeString(string(envelopeResponse.Result))
	if err != nil {
		return nil, err
	}

	return decoded, nil
}

func frame(payload []byte) []byte {
	buffer := bytes.NewBuffer(make([]byte, 0, 4+len(payload)))
	_ = binary.Write(buffer, binary.LittleEndian, uint32(len(payload)))
	buffer.Write(payload)
	return buffer.Bytes()
}

func readFrame(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := readFull(conn, header); err != nil {
		return nil, err
	}

	length := binary.LittleEndian.Uint32(header)
	if length == 0 {
		return nil, fmt.Errorf("secreta error: empty response")
	}

	payload := make([]byte, length)
	if _, err := readFull(conn, payload); err != nil {
		return nil, err
	}

	return payload, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func newRequestID() (string, error) {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16]), nil
}
