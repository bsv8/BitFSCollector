package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConsoleServesHTML(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		req := httptest.NewRequest(method, "/", nil)
		rec := httptest.NewRecorder()
		Handler(rec, req)
		res := rec.Result()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("%s / = %d", method, res.StatusCode)
		}
		if ctype := res.Header.Get("Content-Type"); !strings.HasPrefix(ctype, "text/html") {
			t.Fatalf("content-type = %q", ctype)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	Handler(rec, req)
	body := rec.Body.String()
	for _, marker := range []string{"v1/submissions", "X-BitFSCollector-Signature", "cc-cli", "SigVersion", "archiveId"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("console page missing %q", marker)
		}
	}
	// 非根路径与非 GET/HEAD 保持 404/405，不吞提交接口之外的路径。
	notFound := httptest.NewRecorder()
	Handler(notFound, httptest.NewRequest(http.MethodGet, "/nope", nil))
	if notFound.Code != http.StatusNotFound {
		t.Fatalf("GET /nope = %d", notFound.Code)
	}
	// 图标路由：同源 SVG，可被 link 引用。
	iconRec := httptest.NewRecorder()
	Handler(iconRec, httptest.NewRequest(http.MethodGet, "/icon.svg", nil))
	iconRes := iconRec.Result()
	if iconRes.StatusCode != http.StatusOK {
		t.Fatalf("GET /icon.svg = %d", iconRes.StatusCode)
	}
	if ctype := iconRes.Header.Get("Content-Type"); ctype != "image/svg+xml" {
		t.Fatalf("icon content-type = %q", ctype)
	}
	if body := iconRec.Body.String(); !strings.HasPrefix(strings.TrimSpace(body), "<svg") || !strings.Contains(body, "</svg>") {
		t.Fatal("icon body is not SVG")
	}
}
