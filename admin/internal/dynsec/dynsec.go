// Package dynsec talks to Mosquitto's Dynamic Security plugin over MQTT. Commands are
// published to $CONTROL/dynamic-security/v1 and answered on .../response; replies are
// matched to requests by correlationData.
package dynsec

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const (
	commandTopic  = "$CONTROL/dynamic-security/v1"
	responseTopic = "$CONTROL/dynamic-security/v1/response"
)

// ErrUnavailable means the broker could not be reached or did not answer in time.
var ErrUnavailable = errors.New("broker unavailable")

// Error is an error reported by the plugin itself, for example "Client already exists".
type Error struct{ Message string }

func (e *Error) Error() string { return e.Message }

// Broker is what the API needs; it is an interface so handlers can be tested without MQTT.
type Broker interface {
	// Do runs one Dynamic Security command and returns its `data` object (may be nil).
	Do(ctx context.Context, command map[string]any) (json.RawMessage, error)
	Connected() bool
}

type Options struct {
	URL        string
	Username   string
	Password   string
	ServerName string
	RootCAPEM  []byte
	ClientID   string
}

type Client struct {
	client  mqtt.Client
	mu      sync.Mutex
	pending map[string]chan response
}

type response struct {
	Command         string          `json:"command"`
	Data            json.RawMessage `json:"data"`
	Error           string          `json:"error"`
	CorrelationData string          `json:"correlationData"`
}

func New(opts Options) (*Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(opts.RootCAPEM) {
		return nil, fmt.Errorf("root CA PEM contains no certificate")
	}
	c := &Client{pending: map[string]chan response{}}
	mo := mqtt.NewClientOptions().
		AddBroker(opts.URL).
		SetClientID(opts.ClientID).
		SetUsername(opts.Username).
		SetPassword(opts.Password).
		SetCleanSession(true).
		SetKeepAlive(30 * time.Second).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(5 * time.Second).
		// Verify the broker against the NM Root CA; ServerName lets us dial the
		// internal address while checking the certificate for the public hostname.
		SetTLSConfig(&tls.Config{RootCAs: pool, ServerName: opts.ServerName, MinVersion: tls.VersionTLS12}).
		SetOnConnectHandler(func(cl mqtt.Client) {
			token := cl.Subscribe(responseTopic, 1, c.onResponse)
			if token.Wait() && token.Error() != nil {
				slog.Error("dynsec: subscribe failed", "error", token.Error())
				return
			}
			slog.Info("dynsec: connected to broker")
		}).
		SetConnectionLostHandler(func(_ mqtt.Client, err error) {
			slog.Warn("dynsec: connection lost", "error", err)
		})
	c.client = mqtt.NewClient(mo)
	c.client.Connect() // retries in the background; readiness is reported by Connected()
	return c, nil
}

func (c *Client) Connected() bool { return c.client.IsConnectionOpen() }

func (c *Client) Close() { c.client.Disconnect(250) }

func (c *Client) onResponse(_ mqtt.Client, msg mqtt.Message) {
	var envelope struct {
		Responses []response `json:"responses"`
	}
	if err := json.Unmarshal(msg.Payload(), &envelope); err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, r := range envelope.Responses {
		if ch, ok := c.pending[r.CorrelationData]; ok {
			ch <- r
			delete(c.pending, r.CorrelationData)
		}
	}
}

func (c *Client) Do(ctx context.Context, command map[string]any) (json.RawMessage, error) {
	if !c.Connected() {
		return nil, ErrUnavailable
	}
	id := make([]byte, 12)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	correlation := hex.EncodeToString(id)

	reply := make(chan response, 1)
	c.mu.Lock()
	c.pending[correlation] = reply
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, correlation)
		c.mu.Unlock()
	}()

	body := map[string]any{}
	for k, v := range command {
		body[k] = v
	}
	body["correlationData"] = correlation
	payload, err := json.Marshal(map[string]any{"commands": []any{body}})
	if err != nil {
		return nil, err
	}
	token := c.client.Publish(commandTopic, 1, false, payload)
	if !token.WaitTimeout(5*time.Second) || token.Error() != nil {
		return nil, ErrUnavailable
	}

	select {
	case r := <-reply:
		if r.Error != "" {
			return nil, &Error{Message: r.Error}
		}
		return r.Data, nil
	case <-ctx.Done():
		return nil, ErrUnavailable
	case <-time.After(10 * time.Second):
		return nil, ErrUnavailable
	}
}
