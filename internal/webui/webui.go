// Package webui 前端静态资源(go:embed 单二进制,切片 8a)。
//
// 构建管线:frontend/ 下 `npm run build`(vite outDir 指向本包 dist/)
// → go build 时嵌进 fengtu 二进制。dist 是构建产物不入库(见 .gitignore),
// 唯一入库的是 placeholder.html——未跑前端构建时,二进制服务占位页
// (如实提示,不装死),API 不受影响的。
package webui

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"strings"
)

//go:embed all:dist
var dist embed.FS

// Handler SPA 静态服务:GET/HEAD 非 /api/ 路径 → dist 内资源;
// 找不到的回退 index.html(前端路由:/login、/cases/:id);
// index.html 都没有(未构建)回退占位页,如实提示构建方法。
func Handler() http.Handler {
	sub, err := fs.Sub(dist, "dist")
	if err != nil {
		// 编译期布局是定的,走不到;防御性如实 500
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "前端资源未嵌入(构建异常)", http.StatusInternalServerError)
		})
	}
	// serve 直接按名出文件(不走 FileServer 路径改写——「/index.html → /」
	// 规范化重定向会让 SPA 回退变 301;Content-Type 按扩展名嗅探)。
	serve := func(name string, w http.ResponseWriter, r *http.Request) bool {
		f, err := sub.Open(name)
		if err != nil {
			return false
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil || st.IsDir() {
			return false
		}
		rs, ok := f.(io.ReadSeeker)
		if !ok {
			return false
		}
		http.ServeContent(w, r, name, st.ModTime(), rs)
		return true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p != "" && serve(p, w, r) {
			return
		}
		// SPA 回退:前端路由交给 index.html;未构建则占位页(如实)
		if serve("index.html", w, r) {
			return
		}
		serve("placeholder.html", w, r)
	})
}
