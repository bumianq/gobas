// Package server 提供 REST API + SSE + Web GUI。
package server

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"gobas/internal/server/web"
	"gobas/internal/service"
)

// Server HTTP 服务。
type Server struct {
	svc *service.Service
}

// New 构建 Server。
func New(svc *service.Service) *Server {
	return &Server{svc: svc}
}

// Handler 返回路由。
func (s *Server) Handler() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware)
	r.Use(middleware.SetHeader("X-Content-Type-Options", "nosniff"))

	r.Get("/api/v1/healthz", s.handleHealth)

	r.Route("/api/v1", func(r chi.Router) {
		// 认证中间件：保护全部业务接口（healthz/login/status 放行，见 auth.go）
		r.Use(s.authMiddleware)
		// 数据实时性（模板集 POC 数、扫描进度等），禁止浏览器启发式缓存 API 响应
		r.Use(middleware.NoCache)

		r.Post("/auth/login", s.handleLogin)
		r.Post("/auth/logout", s.handleLogout)
		r.Post("/auth/change-password", s.handleChangePassword)
		r.Get("/auth/status", s.handleAuthStatus)

		r.Post("/sync", s.handleSync)
		r.Get("/sync/events", s.handleSyncEvents)
		r.Get("/sync/status", s.handleSyncStatus)
		r.Get("/settings", s.handleSettings)

		r.Get("/pocs", s.handleListPOCs)
		r.Post("/pocs/index", s.handleIndexPOCs)
		r.Get("/pocs/index/status", s.handleIndexStatus)
		r.Get("/pocs/index/events", s.handleIndexEvents)
		r.Get("/pocs/stats", s.handlePOCStats)
		r.Post("/pocs/custom", s.handleAddCustomPOC)
		r.Put("/pocs/custom/{id}", s.handleUpdateCustomPOC)
		r.Delete("/pocs/custom/{id}", s.handleDeleteCustomPOC)
		r.Get("/pocs/{id}/content", s.handleGetPOCContent)
		r.Get("/pocs/{id}", s.handleGetPOC)

		r.Get("/poc-sets", s.handleListPOCSets)
		r.Post("/poc-sets", s.handleCreatePOCSet)
		r.Get("/poc-sets/{id}", s.handleGetPOCSet)
		r.Put("/poc-sets/{id}", s.handleUpdatePOCSet)
		r.Delete("/poc-sets/{id}", s.handleDeletePOCSet)
		r.Post("/poc-sets/{id}/pocs", s.handleAddPOCsToSet)
		r.Delete("/poc-sets/{id}/pocs", s.handleRemovePOCsFromSet)

		r.Post("/targets", s.handleAddTargets)
		r.Get("/targets", s.handleListTargets)
		r.Post("/targets/probe", s.handleProbeTargets)
		r.Delete("/targets/{id}", s.handleDeleteTarget)

		r.Post("/scans", s.handleCreateScan)
		r.Get("/scans", s.handleListScans)
		r.Get("/scans/{id}", s.handleGetScan)
		r.Get("/scans/{id}/results", s.handleScanResults)
		r.Post("/scans/{id}/results/verdict", s.handleUpdateScanVerdicts)
		r.Get("/scans/{id}/traffic", s.handleScanTraffic)
		r.Get("/scans/{id}/dump", s.handleScanTrafficDump)
		r.Post("/scans/{id}/cancel", s.handleCancelScan)
		r.Delete("/scans/{id}", s.handleDeleteScan)
		r.Get("/scans/{id}/events", s.handleScanEvents) // SSE
		r.Get("/scans/{id}/report", s.handleReport)
	})

	// Web GUI 静态资源（embed 嵌入，独立运行零外部文件；
	// no-cache 保证升级二进制后浏览器不残留旧版 JS）
	staticFS, _ := fs.Sub(web.Static, "static")
	fileServer := http.FileServer(http.FS(staticFS))
	r.Handle("/static/*", middleware.NoCache(http.StripPrefix("/static/", fileServer)))
	r.Get("/", s.handleIndex)
	r.NotFound(s.handleIndex) // SPA hash 路由兜底
	return r
}

// handleIndex 输出 GUI 入口页。
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	data, err := web.Static.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "index.html missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(data)
}

// ListenAndServe 启动 HTTP 服务。
func (s *Server) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, s.Handler())
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
