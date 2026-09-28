-- 0.27.0-ai-providers:厂商预设表 + 协议列 + 模型清单拉取。
-- ai_settings 补 protocol 列(厂商线格式):
--   openai-compatible = 默认,DeepSeek/OpenAI/通义/智谱/Moonshot/自定义(及
--                       ollama 对话)都走 OpenAI Chat Completions 线格式;
--   anthropic         = Anthropic 原生线格式(norma FormatAnthropic);
--   ollama            = 本地档(对话仍走其 OpenAI 兼容端点,本列只记档位;
--                       拉模型走原生 /api/tags)。
-- 存量行由 DEFAULT 补 openai-compatible——已存 deepseek 配置零改动,向后兼容。
ALTER TABLE ai_settings
    ADD COLUMN IF NOT EXISTS protocol TEXT NOT NULL DEFAULT 'openai-compatible'
        CHECK (protocol IN ('openai-compatible', 'anthropic', 'ollama'));
