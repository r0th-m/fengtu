// 联通性自测(切片十一,照 ARTEX testWebSearch/testLLM 形态):
// 系统配置页「测试」钮的后端——真发一个 HEAD/查询,如实回 ok+细节。
// 单测经 Deps.ProxyClient/SearchProbe 注入或 httptest 打全链,不真连外网。
package agentloop

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/norma/tool"
)

// ProbeResult 联通性自测回执(永远 200 呈现;ok=false 时 detail 是失败原文)。
type ProbeResult struct {
	OK      bool   `json:"ok"`
	Detail  string `json:"detail"`            // 成功:状态码/条数;失败:错误原文
	Target  string `json:"target,omitempty"`  // 代理自测:HEAD 目标(当前 base_url)
	Backend string `json:"backend,omitempty"` // 搜索自测:实际用的后端
}

// proxyHTTPClient 代理 HTTP 客户端(与 norma llm provider 同口径:
// http/https/socks5;空=直连,走 *_PROXY 环境变量)。
func proxyHTTPClient(proxy string) (*http.Client, error) {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if proxy == "" {
		tr.Proxy = http.ProxyFromEnvironment
		return &http.Client{Transport: tr, Timeout: 10 * time.Second}, nil
	}
	u, err := url.Parse(proxy)
	if err != nil {
		return nil, fmt.Errorf("代理 URL 无法解析: %w", err)
	}
	switch u.Scheme {
	case "http", "https", "socks5": // net/http Transport.Proxy 支持
	default:
		return nil, fmt.Errorf("代理须带 scheme http://|https://|socks5://(收到 %q)", proxy)
	}
	tr.Proxy = http.ProxyURL(u)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}, nil
}

// ProbeProxy 代理联通性自测:经该代理对当前 base_url(LLM 厂商端点)发一个
// HEAD,如实回成败。proxy 参数取表单原值(空=直连),先测后存不用落库。
func (s *Service) ProbeProxy(ctx context.Context, proxy string) ProbeResult {
	proxy = strings.TrimSpace(proxy)
	cfg, err := s.resolveConfig(ctx)
	if err != nil {
		return ProbeResult{OK: false, Detail: "配置读取失败: " + err.Error()}
	}
	target := cfg.BaseURL
	if target == "" {
		target = defaultBaseURL
	}
	newClient := s.deps.ProxyClient
	if newClient == nil {
		newClient = proxyHTTPClient
	}
	client, err := newClient(proxy)
	if err != nil {
		return ProbeResult{OK: false, Target: target, Detail: err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return ProbeResult{OK: false, Target: target, Detail: "目标 URL 非法: " + err.Error()}
	}
	resp, err := client.Do(req)
	if err != nil {
		return ProbeResult{OK: false, Target: target, Detail: err.Error()}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	via := "经代理 " + proxy
	if proxy == "" {
		via = "直连"
	}
	return ProbeResult{OK: true, Target: target,
		Detail: fmt.Sprintf("%s HEAD %s → HTTP %d", via, target, resp.StatusCode)}
}

// ProbeSearch 联网搜索自测(照 ARTEX testWebSearch):后端取表单值(空=已存),
// key 空=回退已存密文解密;代理用已存全局代理(与真实工具同一路径)。真发一次
// 查询,如实回条数/错误。
func (s *Service) ProbeSearch(ctx context.Context, backend, key string) ProbeResult {
	cfg, err := s.resolveConfig(ctx)
	if err != nil {
		return ProbeResult{OK: false, Detail: "配置读取失败: " + err.Error()}
	}
	backend = strings.TrimSpace(backend)
	if backend == "" {
		backend = cfg.WebSearchBackend
	}
	apiKey := strings.TrimSpace(key)
	if apiKey == "" {
		apiKey = cfg.SearchAPIKey // 表单留空=用已存 key(key 永不回显,同 ARTEX)
	}
	wsCfg := tool.WebSearchConfig{
		Backend:      backend,
		BraveAPIKey:  apiKey,
		TavilyAPIKey: apiKey,
		Proxy:        cfg.GlobalProxy, // 搜索自测与真实工具同走全局代理
	}
	probe := s.deps.SearchProbe
	if probe == nil {
		probe = tool.WebSearchProbe
	}
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	results, err := probe(cctx, wsCfg, "test", 3)
	if err != nil {
		return ProbeResult{OK: false, Backend: backend, Detail: err.Error()}
	}
	if len(results) == 0 {
		return ProbeResult{OK: false, Backend: backend,
			Detail: "搜索返回 0 条结果(可能被限流或代理不通)"}
	}
	return ProbeResult{OK: true, Backend: backend,
		Detail: fmt.Sprintf("返回 %d 条结果", len(results))}
}
