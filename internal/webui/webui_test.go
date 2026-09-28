package webui

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
)

// SPA 回退:未知 GET 路径 → index.html(构建后)或占位页(未构建),
// 两者必居其一,且不能 404;非 GET 方法 404。
func TestHandlerSPAFallback(t *testing.T) {
	h := Handler()

	r := httptest.NewRequest("GET", "/cases/abc-123", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("SPA 回退应 200,实得 %d", w.Code)
	}
	body, _ := io.ReadAll(w.Result().Body)
	if !strings.Contains(string(body), "<html") {
		t.Fatalf("回退应返回 HTML 页(占位或构建产物),实得: %.80s", body)
	}

	r2 := httptest.NewRequest("POST", "/cases/abc", nil)
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)
	if w2.Code != 404 {
		t.Fatalf("非 GET 应 404,实得 %d", w2.Code)
	}
}

// 占位纪律:dist 至少含 placeholder.html(未构建时二进制如实提示)。
func TestPlaceholderEmbedded(t *testing.T) {
	h := Handler()
	r := httptest.NewRequest("GET", "/placeholder.html", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("placeholder.html 必须嵌入,实得 %d", w.Code)
	}
	body, _ := io.ReadAll(w.Result().Body)
	if !strings.Contains(string(body), "前端尚未构建") {
		t.Fatalf("占位页须含如实构建提示")
	}
}
