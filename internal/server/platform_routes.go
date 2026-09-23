package server

import (
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"xianyu-go/internal/auth"
	"xianyu-go/internal/db"
)

func (s *Server) mountPlatformRoutes(r chi.Router) {
	if s.platformServiceToken == "" { return }
	r.Route("/api/platform/v1", func(r chi.Router) {
		r.Use(s.platformAuth)
		r.Post("/qr-login/generate", s.generateQRLogin)
		r.Get("/qr-login/status/{session_id}", s.checkQRLoginStatusAndPersist)
		r.Post("/chat/messages", s.sendChatMessage)
		r.Post("/chat/images", s.sendChatImage)
		r.Delete("/accounts/{cid}", s.deleteCookie)
	})
}

func (s *Server) platformAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" || subtle.ConstantTimeCompare([]byte(token), []byte(s.platformServiceToken)) != 1 { writeErr(w, http.StatusUnauthorized, "平台服务未授权"); return }
		admin, err := s.Auth.Store.Users.GetByUsername(r.Context(), "admin")
		if err != nil || admin == nil { writeErr(w, http.StatusServiceUnavailable, "平台管理员未初始化"); return }
		session := &db.Session{SessionID: "platform-service", UserID: admin.ID, Username: admin.Username, IsAdmin: admin.IsAdmin, ExpiresAt: time.Now().Add(time.Minute).Unix()}
		next.ServeHTTP(w, r.WithContext(auth.WithSession(r.Context(), session)))
	})
}