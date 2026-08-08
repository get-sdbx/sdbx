package cmd

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/get-sdbx/sdbx/internal/broker"
	"github.com/spf13/cobra"
)

var (
	consoleAddr      string
	consoleTokenFile string
)

var consoleCmd = &cobra.Command{
	Use:   "console",
	Short: "Print the authenticated local console URL",
	Long: `Print a local management-console URL containing an out-of-band
credential in its URL fragment.

The fragment is not sent in the HTTP request. The console moves it into browser
session storage and removes it from the address bar before loading management
data. Run this command only as a trusted local operator who can read the
protected console token.

For remote recovery, forward the packaged loopback recovery listener and pass
its local endpoint explicitly:

    ssh -L 18778:127.0.0.1:18778 operator@your-sdbx-host
    sdbx console --addr 127.0.0.1:18778`,
	Args: cobra.NoArgs,
	RunE: runConsole,
}

func init() {
	rootCmd.AddCommand(consoleCmd)
	consoleCmd.Flags().StringVar(
		&consoleAddr,
		"addr",
		"127.0.0.1:18777",
		"browser-visible loopback console address",
	)
	consoleCmd.Flags().StringVar(
		&consoleTokenFile,
		"web-token-file",
		"/var/run/sdbx/console.token",
		"protected browser console token file",
	)
}

func runConsole(_ *cobra.Command, _ []string) error {
	if err := validateServeAddress(consoleAddr, false); err != nil {
		return err
	}
	token, err := broker.LoadTokenFile(consoleTokenFile)
	if err != nil {
		return fmt.Errorf("load browser console credentials: %w", err)
	}
	consoleURL := authenticatedConsoleURL(consoleAddr, token)
	if IsJSONOutput() {
		data, marshalErr := json.MarshalIndent(map[string]string{
			"url": consoleURL,
		}, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		fmt.Println(string(data))
		return nil
	}
	fmt.Println(consoleURL)
	return nil
}

func authenticatedConsoleURL(addr, token string) string {
	target := url.URL{
		Scheme:   "http",
		Host:     addr,
		Path:     "/",
		Fragment: "token=" + token,
	}
	return target.String()
}
