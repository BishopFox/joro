package api

import "net/http"

func (s *APIServer) handleDownloadCACert(w http.ResponseWriter, r *http.Request) {
	if s.ca == nil {
		writeError(w, http.StatusNotFound, "CA not initialised")
		return
	}
	w.Header().Set("Content-Type", "application/x-x509-ca-cert")
	w.Header().Set("Content-Disposition", `attachment; filename="joro-ca.crt"`)
	w.WriteHeader(http.StatusOK)
	w.Write(s.ca.CertPEM) //nolint:errcheck
}
