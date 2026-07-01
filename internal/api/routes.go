package api

import "net/http"

func registerRoutes(s *APIServer, mux *http.ServeMux) {
	// WebSocket
	mux.HandleFunc("/ws", s.hub.ServeWS)

	// Mode
	mux.HandleFunc("GET /api/v1/mode", s.handleGetMode)

	// Theme CSS for plugin iframes
	mux.HandleFunc("GET /api/v1/theme/variables.css", s.handleThemeVariables)

	// System info
	mux.HandleFunc("GET /api/v1/system/info", s.handleSystemInfo)

	// Settings
	mux.HandleFunc("GET /api/v1/settings", s.handleGetSettings)
	mux.HandleFunc("PUT /api/v1/settings", s.handleUpdateSettings)

	// Callback routes (both modes - handler logic differs per mode)
	mux.HandleFunc("GET /api/v1/callbacks/tokens", s.handleListTokens)
	mux.HandleFunc("POST /api/v1/callbacks/tokens", s.handleCreateToken)
	mux.HandleFunc("DELETE /api/v1/callbacks/tokens/{id}", s.handleDeleteToken)
	mux.HandleFunc("GET /api/v1/callbacks/interactions", s.handleListInteractions)
	mux.HandleFunc("DELETE /api/v1/callbacks/interactions", s.handleClearInteractions)
	mux.HandleFunc("GET /api/v1/callbacks/config", s.handleGetCallbackConfig)
	mux.HandleFunc("PUT /api/v1/callbacks/config", s.handleUpdateCallbackConfig)

	// XSS Hunter routes (both modes - handler logic differs per mode)
	mux.HandleFunc("GET /api/v1/xss/probes", s.handleListProbes)
	mux.HandleFunc("POST /api/v1/xss/probes", s.handleCreateProbe)
	mux.HandleFunc("DELETE /api/v1/xss/probes/{id}", s.handleDeleteProbe)
	mux.HandleFunc("GET /api/v1/xss/probes/{id}/payloads", s.handleGetPayloads)
	mux.HandleFunc("GET /api/v1/xss/fires", s.handleListFires)
	mux.HandleFunc("GET /api/v1/xss/fires/{id}", s.handleGetFire)
	mux.HandleFunc("DELETE /api/v1/xss/fires/{id}", s.handleDeleteFire)
	mux.HandleFunc("DELETE /api/v1/xss/fires", s.handleClearFires)
	mux.HandleFunc("PUT /api/v1/xss/probes/{id}", s.handleUpdateProbe)
	mux.HandleFunc("GET /api/v1/xss/fires/{id}/pages", s.handleListCollectedPages)
	mux.HandleFunc("GET /api/v1/xss/pages/{id}", s.handleGetCollectedPage)
	mux.HandleFunc("GET /api/v1/xss/config", s.handleGetXSSConfig)
	mux.HandleFunc("PUT /api/v1/xss/config", s.handleUpdateXSSConfig)

	if s.listenerMode {
		if s.teamServerMode {
			// Team routes (direct DB access on teamserver).
			mux.HandleFunc("GET /api/v1/team/chat", s.handleListChatMessages)
			mux.HandleFunc("POST /api/v1/team/chat", s.handleCreateChatMessage)
			mux.HandleFunc("GET /api/v1/team/users", s.handleListActiveUsers)
			mux.HandleFunc("POST /api/v1/team/presence", s.handleTeamPresence)
			mux.HandleFunc("POST /api/v1/team/nickname", s.handleTeamRename)
			mux.HandleFunc("GET /api/v1/team/notes/hosts", s.handleListTeamNoteHosts)
			mux.HandleFunc("GET /api/v1/team/notes", s.handleListTeamNotes)
			mux.HandleFunc("POST /api/v1/team/notes", s.handleCreateTeamNote)
			mux.HandleFunc("PUT /api/v1/team/notes/{id}", s.handleUpdateTeamNote)
			mux.HandleFunc("DELETE /api/v1/team/notes/{id}", s.handleDeleteTeamNote)
			mux.HandleFunc("GET /api/v1/team/flagged", s.handleListFlagged)
			mux.HandleFunc("POST /api/v1/team/flagged", s.handleCreateFlagged)
			mux.HandleFunc("GET /api/v1/team/flagged/{id}", s.handleGetFlagged)
			mux.HandleFunc("DELETE /api/v1/team/flagged/{id}", s.handleDeleteFlagged)
			mux.HandleFunc("GET /api/v1/team/configs", s.handleListSharedConfigs)
			mux.HandleFunc("POST /api/v1/team/configs", s.handleCreateSharedConfig)
			mux.HandleFunc("GET /api/v1/team/configs/{id}", s.handleGetSharedConfig)
			mux.HandleFunc("DELETE /api/v1/team/configs/{id}", s.handleDeleteSharedConfig)
			mux.HandleFunc("POST /api/v1/team/collab", s.handleCreateCollab)
			mux.HandleFunc("GET /api/v1/team/collab/{id}", s.handleGetCollab)
			mux.HandleFunc("POST /api/v1/team/collab/{id}/accept", s.handleAcceptCollab)
		}
		return
	}

	// Proxy mode routes
	// Version / Update
	mux.HandleFunc("GET /api/v1/system/version", s.handleVersionInfo)
	mux.HandleFunc("POST /api/v1/system/restart", s.handleRestart)
	mux.HandleFunc("POST /api/v1/system/update", s.handleUpdate)
	mux.HandleFunc("POST /api/v1/system/check-update", s.handleCheckUpdate)

	// Sitemap
	mux.HandleFunc("GET /api/v1/sitemap", s.handleGetSitemap)

	// HTTP history
	mux.HandleFunc("GET /api/v1/requests", s.handleListRequests)
	mux.HandleFunc("GET /api/v1/requests/{id}", s.handleGetRequest)
	mux.HandleFunc("DELETE /api/v1/requests", s.handleClearRequests)

	// Intercept
	mux.HandleFunc("GET /api/v1/intercept", s.handleGetInterceptQueue)
	mux.HandleFunc("PUT /api/v1/intercept/enabled", s.handleToggleIntercept)
	mux.HandleFunc("POST /api/v1/intercept/{id}/forward", s.handleForwardRequest)
	mux.HandleFunc("POST /api/v1/intercept/{id}/drop", s.handleDropRequest)

	// Manipulate
	mux.HandleFunc("POST /api/v1/manipulate/send", s.handleManipulateSend)
	mux.HandleFunc("POST /api/v1/manipulate/ws/connect", s.handleManipulateWSConnect)
	mux.HandleFunc("POST /api/v1/manipulate/ws/{id}/send", s.handleManipulateWSSend)
	mux.HandleFunc("POST /api/v1/manipulate/ws/{id}/disconnect", s.handleManipulateWSDisconnect)

	// Fuzzer
	mux.HandleFunc("POST /api/v1/fuzzer/start", s.handleFuzzerStart)
	mux.HandleFunc("POST /api/v1/fuzzer/{id}/stop", s.handleFuzzerStop)
	mux.HandleFunc("GET /api/v1/fuzzer/campaigns", s.handleFuzzerListCampaigns)
	mux.HandleFunc("GET /api/v1/fuzzer/campaigns/{id}", s.handleFuzzerGetCampaign)
	mux.HandleFunc("GET /api/v1/fuzzer/campaigns/{id}/results/{index}", s.handleFuzzerGetResult)
	mux.HandleFunc("DELETE /api/v1/fuzzer/campaigns/{id}", s.handleFuzzerDeleteCampaign)
	mux.HandleFunc("POST /api/v1/fuzzer/wordlist", s.handleFuzzerUploadWordlist)

	// Web shell generator
	mux.HandleFunc("POST /api/v1/generate", s.handleGenerate)

	// Web shell executor
	mux.HandleFunc("POST /api/v1/execute", s.handleExecute)

	// Scope
	mux.HandleFunc("GET /api/v1/scope", s.handleGetScope)
	mux.HandleFunc("PUT /api/v1/scope/enabled", s.handleSetScopeEnabled)
	mux.HandleFunc("POST /api/v1/scope/rules", s.handleAddScopeRule)
	mux.HandleFunc("DELETE /api/v1/scope/rules/{id}", s.handleDeleteScopeRule)

	// Noise filter
	mux.HandleFunc("GET /api/v1/noise", s.handleGetNoise)
	mux.HandleFunc("PUT /api/v1/noise/enabled", s.handleSetNoiseEnabled)
	mux.HandleFunc("POST /api/v1/noise/patterns", s.handleAddNoisePattern)
	mux.HandleFunc("DELETE /api/v1/noise/patterns/{id}", s.handleDeleteNoisePattern)

	// Match & Replace
	mux.HandleFunc("GET /api/v1/replace", s.handleGetReplace)
	mux.HandleFunc("PUT /api/v1/replace/enabled", s.handleSetReplaceEnabled)
	mux.HandleFunc("POST /api/v1/replace/rules", s.handleAddReplaceRule)
	mux.HandleFunc("DELETE /api/v1/replace/rules/{id}", s.handleDeleteReplaceRule)

	// Custom Data
	mux.HandleFunc("GET /api/v1/customdata", s.handleGetCustomData)
	mux.HandleFunc("PUT /api/v1/customdata/enabled", s.handleSetCustomDataEnabled)
	mux.HandleFunc("POST /api/v1/customdata/items", s.handleAddCustomDataItem)
	mux.HandleFunc("DELETE /api/v1/customdata/items/{id}", s.handleDeleteCustomDataItem)

	// Config save/load
	mux.HandleFunc("GET /api/v1/configs/user", s.handleListUserConfigs)
	mux.HandleFunc("POST /api/v1/configs/user", s.handleSaveUserConfig)
	mux.HandleFunc("PUT /api/v1/configs/user/{name}", s.handleLoadUserConfig)
	mux.HandleFunc("DELETE /api/v1/configs/user/{name}", s.handleDeleteUserConfig)
	mux.HandleFunc("GET /api/v1/configs/project", s.handleListProjectConfigs)
	mux.HandleFunc("POST /api/v1/configs/project", s.handleSaveProjectConfig)
	mux.HandleFunc("PUT /api/v1/configs/project/{name}", s.handleLoadProjectConfig)
	mux.HandleFunc("DELETE /api/v1/configs/project/{name}", s.handleDeleteProjectConfig)
	mux.HandleFunc("GET /api/v1/configs/export", s.handleExportProjectConfig)
	mux.HandleFunc("POST /api/v1/configs/import", s.handleImportSharedConfig)
	mux.HandleFunc("POST /api/v1/configs/apply-shared", s.handleApplySharedConfig)

	// Highlights
	mux.HandleFunc("GET /api/v1/highlights", s.handleGetHighlights)
	mux.HandleFunc("PUT /api/v1/highlights/{id}", s.handleSetHighlight)
	mux.HandleFunc("DELETE /api/v1/highlights", s.handleClearHighlights)

	// WebSocket messages
	mux.HandleFunc("GET /api/v1/ws/messages", s.handleListWSMessages)
	mux.HandleFunc("DELETE /api/v1/ws/messages", s.handleClearWSMessages)

	// Sliver C2
	mux.HandleFunc("GET /api/v1/sliver/status", s.handleSliverStatus)
	mux.HandleFunc("POST /api/v1/sliver/connect", s.handleSliverConnect)
	mux.HandleFunc("POST /api/v1/sliver/disconnect", s.handleSliverDisconnect)
	mux.HandleFunc("GET /api/v1/sliver/sessions", s.handleSliverSessions)
	mux.HandleFunc("POST /api/v1/sliver/execute", s.handleSliverExecute)
	mux.HandleFunc("POST /api/v1/sliver/command", s.handleSliverCommand)
	mux.HandleFunc("GET /api/v1/sliver/download/{id}", s.handleSliverDownload)
	mux.HandleFunc("POST /api/v1/sliver/upload", s.handleSliverUpload)

	// Notes
	mux.HandleFunc("GET /api/v1/notes/hosts", s.handleListNoteHosts)
	mux.HandleFunc("GET /api/v1/notes", s.handleListNotes)
	mux.HandleFunc("POST /api/v1/notes", s.handleCreateNote)
	mux.HandleFunc("PUT /api/v1/notes/{id}", s.handleUpdateNote)
	mux.HandleFunc("DELETE /api/v1/notes/{id}", s.handleDeleteNote)

	// CA cert download
	mux.HandleFunc("GET /api/v1/certs/ca.crt", s.handleDownloadCACert)

	// Team routes (proxy-side, forwarded to teamserver via proxyToListener).
	mux.HandleFunc("GET /api/v1/team/chat", s.handleProxyTeamChat)
	mux.HandleFunc("POST /api/v1/team/chat", s.handleProxyTeamChat)
	mux.HandleFunc("GET /api/v1/team/users", s.handleProxyTeamUsers)
	mux.HandleFunc("POST /api/v1/team/presence", s.handleProxyTeamPresence)
	mux.HandleFunc("GET /api/v1/team/notes/hosts", s.handleProxyTeamNotes)
	mux.HandleFunc("GET /api/v1/team/notes", s.handleProxyTeamNotes)
	mux.HandleFunc("POST /api/v1/team/notes", s.handleProxyTeamNotes)
	mux.HandleFunc("PUT /api/v1/team/notes/{id}", s.handleProxyTeamNotes)
	mux.HandleFunc("DELETE /api/v1/team/notes/{id}", s.handleProxyTeamNotes)
	mux.HandleFunc("GET /api/v1/team/flagged", s.handleProxyTeamFlagged)
	mux.HandleFunc("POST /api/v1/team/flagged", s.handleProxyTeamFlagged)
	mux.HandleFunc("GET /api/v1/team/flagged/{id}", s.handleProxyTeamFlagged)
	mux.HandleFunc("DELETE /api/v1/team/flagged/{id}", s.handleProxyTeamFlagged)
	mux.HandleFunc("GET /api/v1/team/configs", s.handleProxyTeamConfigs)
	mux.HandleFunc("POST /api/v1/team/configs", s.handleProxyTeamConfigs)
	mux.HandleFunc("GET /api/v1/team/configs/{id}", s.handleProxyTeamConfigs)
	mux.HandleFunc("DELETE /api/v1/team/configs/{id}", s.handleProxyTeamConfigs)
	mux.HandleFunc("POST /api/v1/team/collab", s.handleProxyTeamCollab)
	mux.HandleFunc("GET /api/v1/team/collab/{id}", s.handleProxyTeamCollab)
	mux.HandleFunc("POST /api/v1/team/collab/{id}/accept", s.handleProxyTeamCollab)

	// Plugin routes (dynamic, based on loaded plugins).
	registerPluginRoutes(s, mux)
}
