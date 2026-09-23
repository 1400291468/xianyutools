package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPlatformRoutesRequireServiceTokenAndInjectServiceSession(t *testing.T) {
	srv, _, cleanup := newTestServer(t)
	defer cleanup()

	t.Run("未配置时不注册路由", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/platform/v1/qr-login/status/missing", nil)
		rec := httptest.NewRecorder()
		srv.Router().ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status=%d, want %d", rec.Code, http.StatusNotFound)
		}
	})

	srv.platformServiceToken = "platform-test-token"
	router := srv.Router()

	t.Run("缺少令牌被拒绝", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/platform/v1/qr-login/status/missing", nil)
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("错误令牌被拒绝", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/platform/v1/qr-login/status/missing", nil)
		req.Header.Set("Authorization", "Bearer incorrect")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("有效令牌进入受服务会话保护的处理器", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/platform/v1/qr-login/status/missing", nil)
		req.Header.Set("Authorization", "Bearer platform-test-token")
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("status=%d, want %d", rec.Code, http.StatusNotFound)
		}
	})
}
