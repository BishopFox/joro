package api

import "context"

// StartAnomalyLoop launches the per-host anomaly engine in the background,
// mirroring StartDetectLoop. It runs whether or not the feature is enabled; the
// engine cheaply no-ops each cycle while detect.Config.AnomalyEnabled is off, so
// a live toggle needs no restart.
func (s *APIServer) StartAnomalyLoop(ctx context.Context) {
	if s.anomalyEngine == nil {
		return
	}
	go s.anomalyEngine.Run(ctx)
}
