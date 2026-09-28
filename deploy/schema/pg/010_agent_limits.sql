-- 切片十一(0.16.0-agent-limits,ARTEX 系统设置对齐刀):
--   - agent_concurrency 意图引擎派发 worker 的全局并发上限(默认 4;超限排队,
--     过程流如实记「排队中(并发上限 N)」;改配置对之后的派发即时生效);
--   - global_proxy 全局出口代理(http/https/socks5 URL,空=直连),生效范围:
--     LLM 厂商请求 + 联网搜索请求;
--   - web_search_* 联网搜索开关 + 后端(ddgs 免 key / brave-free / tavily 需 key);
--     搜索 key 与 api_key 同纪律:只存 AES-GCM 密文(search_api_key_enc)。
-- 证据链纪律:web_search 结果是参考不是证据,锚点仍只能锚案件采集物
-- (工具描述写死该口径,见 agentloop/tools.go)。
ALTER TABLE ai_settings
    ADD COLUMN IF NOT EXISTS agent_concurrency INT NOT NULL DEFAULT 4
        CHECK (agent_concurrency > 0),
    ADD COLUMN IF NOT EXISTS global_proxy TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS web_search_enabled BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS web_search_backend TEXT NOT NULL DEFAULT 'ddgs'
        CHECK (web_search_backend IN ('ddgs', 'brave-free', 'tavily')),
    ADD COLUMN IF NOT EXISTS search_api_key_enc TEXT NOT NULL DEFAULT '';
