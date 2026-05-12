package api

import (
	"io/fs"
	"net/http"
	"strings"
	"sync"

	joroweb "github.com/BishopFox/joro/web"
)

var (
	themeCSS     string
	themeCSSOnce sync.Once
)

// handleThemeVariables serves all theme CSS variable definitions as a single
// stylesheet. Plugin UIs include this via <link> and set data-theme on their
// own <html> element to activate the correct theme.
func (s *APIServer) handleThemeVariables(w http.ResponseWriter, _ *http.Request) {
	themeCSSOnce.Do(func() {
		var sb strings.Builder
		themesFS, err := fs.Sub(joroweb.Themes, "src/themes")
		if err != nil {
			return
		}
		entries, err := fs.ReadDir(themesFS, ".")
		if err != nil {
			return
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".css") {
				continue
			}
			data, err := fs.ReadFile(themesFS, entry.Name())
			if err != nil {
				continue
			}
			sb.Write(data)
			sb.WriteByte('\n')
		}
		themeCSS = sb.String()
	})

	w.Header().Set("Content-Type", "text/css; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write([]byte(themeCSS)) //nolint:errcheck
}
