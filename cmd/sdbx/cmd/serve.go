package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/get-sdbx/sdbx/internal/broker"
	"github.com/get-sdbx/sdbx/internal/httplifecycle"
	"github.com/get-sdbx/sdbx/internal/securefs"
	"github.com/get-sdbx/sdbx/internal/webui"
	"github.com/spf13/cobra"
)

const (
	maxConsolePublicHostBytes = 1024
	maxConsolePEMBytes        = 1 << 20
)

var (
	serveAddr            string
	serveBrokerSocket    string
	serveBrokerTokenFile string
	serveWebTokenFile    string
	serveTLSCertFile     string
	serveTLSKeyFile      string
	serveClientCAFile    string
	servePublicHostFile  string
	serveRecoveryAddr    string
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the SDBX web console",
	Long: `Run the SDBX management web console.

The console supports two fail-closed access paths: a loopback listener with the
out-of-band browser token, or a mutually authenticated TLS listener reached by
the generated Traefik route after Authelia authorizes an admin.

The packaged remote service also opens a separate HTTP recovery listener on
loopback. Reach that listener from another machine through an SSH tunnel:

    ssh -L 18778:127.0.0.1:18778 operator@your-sdbx-host
    sdbx console --addr 127.0.0.1:18778
    # open the printed fragment-authenticated URL in the local browser

Run the browser-facing process as an unprivileged account. It can perform only
versioned, typed operations exposed by the local sdbxd broker. The broker
socket and client token must be provisioned by sdbxd before starting this
console. Browser clients must obtain the separate protected console credential
through 'sdbx console'; it is never embedded in unauthenticated HTML.`,
	Args: cobra.NoArgs,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().StringVar(&serveAddr, "addr", "127.0.0.1:18777", "HTTP listen address")
	serveCmd.Flags().StringVar(
		&serveBrokerSocket,
		"broker-socket",
		"/var/run/sdbx/sdbxd.sock",
		"sdbxd Unix socket",
	)
	serveCmd.Flags().StringVar(
		&serveBrokerTokenFile,
		"broker-token-file",
		"/var/run/sdbx/client.token",
		"sdbxd client token file",
	)
	serveCmd.Flags().StringVar(
		&serveWebTokenFile,
		"web-token-file",
		"/var/run/sdbx/console.token",
		"out-of-band browser console token file",
	)
	serveCmd.Flags().StringVar(&serveTLSCertFile, "tls-cert-file", "", "server certificate for the Traefik mTLS transport")
	serveCmd.Flags().StringVar(&serveTLSKeyFile, "tls-key-file", "", "server key for the Traefik mTLS transport")
	serveCmd.Flags().StringVar(&serveClientCAFile, "client-ca-file", "", "CA used to authenticate the Traefik client certificate")
	serveCmd.Flags().StringVar(&servePublicHostFile, "public-host-file", "", "protected file containing the canonical remote console hostname")
	serveCmd.Flags().StringVar(&serveRecoveryAddr, "recovery-addr", "", "optional loopback HTTP recovery listener for remote TLS mode")
}

func runServe(command *cobra.Command, _ []string) error {
	remoteTLS := serveTLSCertFile != "" || serveTLSKeyFile != "" ||
		serveClientCAFile != "" || servePublicHostFile != ""
	if err := validateServeAddress(serveAddr, remoteTLS); err != nil {
		return err
	}
	if err := validateRecoveryAddress(
		serveAddr,
		serveRecoveryAddr,
		remoteTLS,
	); err != nil {
		return err
	}
	publicHost := ""
	if remoteTLS {
		var err error
		publicHost, err = loadPublicHostFile(servePublicHostFile)
		if err != nil {
			return err
		}
	}
	ctx := command.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	brokerToken, err := broker.LoadTokenFile(serveBrokerTokenFile)
	if err != nil {
		return fmt.Errorf("load management broker credentials: %w", err)
	}
	operator, err := broker.NewUnixClient(serveBrokerSocket, brokerToken)
	if err != nil {
		return fmt.Errorf("connect management broker: %w", err)
	}
	webToken, err := broker.LoadTokenFile(serveWebTokenFile)
	if err != nil {
		return fmt.Errorf("load browser console credentials: %w", err)
	}

	server, err := webui.New(webui.Options{
		Operator:   operator,
		Token:      webToken,
		PublicHost: publicHost,
	})
	if err != nil {
		return err
	}

	var tlsConfig *tls.Config
	if remoteTLS {
		tlsConfig, err = consoleTLSConfig(
			serveTLSCertFile,
			serveTLSKeyFile,
			serveClientCAFile,
		)
		if err != nil {
			return err
		}
	}

	listener, err := net.Listen("tcp", serveAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", serveAddr, err)
	}

	scheme := "http"
	if remoteTLS {
		scheme = "https"
	}
	fmt.Printf("SDBX console listening on %s://%s\n", scheme, listener.Addr().String())
	if remoteTLS {
		fmt.Printf("Remote console trust is pinned to https://%s through Authelia and Traefik mTLS.\n", publicHost)
	} else {
		fmt.Println("Run 'sdbx console' as an authorized local operator to obtain the browser URL.")
	}
	fmt.Println("Press Ctrl+C to stop.")

	if remoteTLS {
		listener = tls.NewListener(listener, tlsConfig)
	}
	endpoints := []httplifecycle.Endpoint{{
		Name:     "primary",
		Server:   newConsoleHTTPServer(server.Handler(), tlsConfig),
		Listener: listener,
	}}
	if serveRecoveryAddr != "" {
		recoveryListener, listenErr := net.Listen("tcp", serveRecoveryAddr)
		if listenErr != nil {
			_ = listener.Close()
			return fmt.Errorf(
				"failed to listen on recovery address %s: %w",
				serveRecoveryAddr,
				listenErr,
			)
		}
		endpoints = append(endpoints, httplifecycle.Endpoint{
			Name:     "loopback-recovery",
			Server:   newConsoleHTTPServer(server.Handler(), nil),
			Listener: recoveryListener,
		})
		fmt.Printf(
			"Local recovery console listening on http://%s\n",
			recoveryListener.Addr().String(),
		)
	}
	return httplifecycle.ServeGroup(ctx, endpoints, 10*time.Second)
}

func newConsoleHTTPServer(handler http.Handler, tlsConfig *tls.Config) *http.Server {
	return &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      6 * time.Minute,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    16 << 10,
		TLSConfig:         tlsConfig,
	}
}

func validateServeAddress(addr string, remoteMode ...bool) error {
	remoteTLS := len(remoteMode) == 1 && remoteMode[0]
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", addr, err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		if !remoteTLS {
			return fmt.Errorf("web console must bind to a loopback address; got %q", addr)
		}
		return fmt.Errorf("web console address must use an IP literal or localhost; got %q", addr)
	}
	if !ip.IsLoopback() && !remoteTLS {
		return fmt.Errorf("web console must bind to a loopback address; got %q", addr)
	}
	return nil
}

func validateRecoveryAddress(primary, recovery string, remoteTLS bool) error {
	if recovery == "" {
		return nil
	}
	if !remoteTLS {
		return fmt.Errorf("--recovery-addr requires remote TLS mode")
	}
	if err := validateServeAddress(recovery, false); err != nil {
		return fmt.Errorf("invalid recovery listener: %w", err)
	}
	if recovery == primary {
		return fmt.Errorf("recovery and primary console addresses must differ")
	}
	return nil
}

func loadPublicHostFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("--public-host-file is required for remote TLS mode")
	}
	data, err := securefs.ReadRegularFile(path, maxConsolePublicHostBytes)
	if err != nil {
		return "", fmt.Errorf("read remote console hostname: %w", err)
	}
	host := strings.TrimSpace(string(data))
	if host == "" || strings.ContainsAny(host, "/:@\\\x00\r\n\t ") {
		return "", fmt.Errorf("remote console hostname is invalid")
	}
	return host, nil
}

func consoleTLSConfig(certFile, keyFile, caFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" || caFile == "" {
		return nil, fmt.Errorf("--tls-cert-file, --tls-key-file, and --client-ca-file are required together")
	}
	certificatePEM, err := securefs.ReadRegularFile(certFile, maxConsolePEMBytes)
	if err != nil {
		return nil, fmt.Errorf("load remote console server certificate: %w", err)
	}
	keyPEM, err := securefs.ReadRegularFile(keyFile, maxConsolePEMBytes)
	if err != nil {
		return nil, fmt.Errorf("load remote console server key: %w", err)
	}
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load remote console server certificate: %w", err)
	}
	caPEM, err := securefs.ReadRegularFile(caFile, maxConsolePEMBytes)
	if err != nil {
		return nil, fmt.Errorf("load remote console client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("remote console client CA contains no certificate")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}, nil
}
