// 平台设置/key 加密/配置优先级单测。
package agentloop

import (
	"context"
	"strings"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
)

func TestKeyCryptoRoundtrip(t *testing.T) {
	svc, _, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{
		"FENGTU_AI_SECRET": "test-secret",
	})
	enc, err := svc.encryptKey("sk-real-key")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(enc, "sk-real-key") {
		t.Fatal("密文不应含明文")
	}
	dec, err := svc.decryptKey(enc)
	if err != nil || dec != "sk-real-key" {
		t.Fatalf("解密回环失败: %q %v", dec, err)
	}
	// 无密钥:密文在而 FENGTU_AI_SECRET 不在 → 如实报错,不静默当未配置
	svc2, _, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{})
	if _, err := svc2.decryptKey(enc); err == nil {
		t.Fatal("无 master key 应如实报无法解密")
	}
}

func TestResolveConfigPrecedence(t *testing.T) {
	svc, meta, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{
		"FENGTU_AI_API_KEY": "sk-env",
		"FENGTU_AI_MODEL":   "env-model",
	})
	meta.settings = &store.AISettings{ID: 1, Model: "pg-model", OutboundEnabled: true}
	cfg, err := svc.resolveConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// env 优先
	if cfg.APIKey != "sk-env" || cfg.KeySource != "env" || cfg.Model != "env-model" {
		t.Fatalf("env 优先不符: %+v", cfg)
	}
	// 默认档(DeepSeek)
	if cfg.BaseURL != defaultBaseURL || cfg.BudgetTokens != defaultBudget {
		t.Fatalf("默认档不符: %+v", cfg)
	}
}

func TestSaveSettingsPartialAndClearKey(t *testing.T) {
	svc, meta, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{
		"FENGTU_AI_SECRET": "test-secret",
	})
	key := "sk-pg-key"
	if err := svc.SaveSettings(context.Background(), "tester", SettingsInput{
		APIKey: &key, Model: strPtr("pg-model"),
	}); err != nil {
		t.Fatal(err)
	}
	if meta.settings == nil || meta.settings.APIKeyEnc == "" {
		t.Fatal("key 应只存密文")
	}
	// 从零起步:预算落默认(PG CHECK >0 的契约,fake 吃不出真约束,断言兜底)
	if meta.settings.SessionBudgetTokens != defaultBudget {
		t.Fatalf("从零起步预算应为默认 %d: %d", defaultBudget,
			meta.settings.SessionBudgetTokens)
	}
	if strings.Contains(meta.settings.APIKeyEnc, key) {
		t.Fatal("密文不应含明文 key")
	}
	// 部分更新不动已存 key
	if err := svc.SaveSettings(context.Background(), "tester", SettingsInput{
		OutboundEnabled: boolPtr(true),
	}); err != nil {
		t.Fatal(err)
	}
	if meta.settings.APIKeyEnc == "" || !meta.settings.OutboundEnabled {
		t.Fatalf("部分更新不应动 key: %+v", meta.settings)
	}
	// 解密回环(env 无 key 时走 PG)
	cfg, err := svc.resolveConfig(context.Background())
	if err != nil || cfg.APIKey != key || cfg.KeySource != "pg" {
		t.Fatalf("PG key 解密不符: %+v %v", cfg, err)
	}
	// 显式清除
	if err := svc.SaveSettings(context.Background(), "tester", SettingsInput{
		ClearKey: true}); err != nil {
		t.Fatal(err)
	}
	if meta.settings.APIKeyEnc != "" {
		t.Fatal("ClearKey 应清空密文")
	}
	// 非法预算
	bad := int64(-1)
	if err := svc.SaveSettings(context.Background(), "tester", SettingsInput{
		SessionBudgetTokens: &bad}); err == nil {
		t.Fatal("非法预算应拒")
	}
}

// TestIntentBudgetLimits 意图链预算三闸(0.24.0):默认 5/30/200、部分更新、
// 非法值拒、resolveConfig 落 PG 值。
func TestIntentBudgetLimits(t *testing.T) {
	svc, meta, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{
		"FENGTU_AI_SECRET": "test-secret",
	})
	// 从零起步保存:三闸落默认(014 迁移 DEFAULT 同口径)
	if err := svc.SaveSettings(context.Background(), "tester", SettingsInput{}); err != nil {
		t.Fatal(err)
	}
	if meta.settings.IntentFanoutLimit != DefaultIntentFanoutLimit ||
		meta.settings.IntentChapterLimit != DefaultIntentChapterLimit ||
		meta.settings.IntentCaseLimit != DefaultIntentCaseLimit {
		t.Fatalf("从零起步三闸应为默认 5/30/200: %+v", meta.settings)
	}
	cfg, err := svc.PublicConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.IntentFanoutLimit != 5 || cfg.IntentChapterLimit != 30 || cfg.IntentCaseLimit != 200 {
		t.Fatalf("PublicConfig 三闸默认不符: %+v", cfg)
	}
	// 部分更新:只动扇出,其余不动
	if err := svc.SaveSettings(context.Background(), "tester", SettingsInput{
		IntentFanoutLimit: intPtr(3)}); err != nil {
		t.Fatal(err)
	}
	if meta.settings.IntentFanoutLimit != 3 || meta.settings.IntentCaseLimit != 200 {
		t.Fatalf("部分更新不符: %+v", meta.settings)
	}
	cfg, _ = svc.resolveConfig(context.Background())
	if cfg.IntentFanoutLimit != 3 || cfg.IntentChapterLimit != 30 {
		t.Fatalf("resolveConfig 三闸不符: %+v", cfg)
	}
	// 非法值(零/负)逐项拒
	for _, in := range []SettingsInput{
		{IntentFanoutLimit: intPtr(0)},
		{IntentChapterLimit: intPtr(-1)},
		{IntentCaseLimit: intPtr(0)},
	} {
		if err := svc.SaveSettings(context.Background(), "tester", in); err == nil {
			t.Fatalf("非法闸值应拒: %+v", in)
		}
	}
}

// TestSettingsProtocol 协议列(0.27.0):默认 openai-compatible、合法值落库、
// 非法值拒、存量行(Protocol 空)向后兼容回默认、env 覆盖。
func TestSettingsProtocol(t *testing.T) {
	svc, meta, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{
		"FENGTU_AI_SECRET": "test-secret",
	})
	// 从零起步:协议默认 openai-compatible
	cfg, err := svc.resolveConfig(context.Background())
	if err != nil || cfg.Protocol != ProtocolOpenAICompat {
		t.Fatalf("默认协议不符: %+v %v", cfg, err)
	}
	// 合法值落库 + resolve 带出
	if err := svc.SaveSettings(context.Background(), "tester", SettingsInput{
		Protocol: strPtr(ProtocolAnthropic)}); err != nil {
		t.Fatal(err)
	}
	if meta.settings.Protocol != ProtocolAnthropic {
		t.Fatalf("协议未落库: %+v", meta.settings)
	}
	cfg, _ = svc.resolveConfig(context.Background())
	if cfg.Protocol != ProtocolAnthropic {
		t.Fatalf("resolve 协议不符: %+v", cfg)
	}
	// 非法值拒
	if err := svc.SaveSettings(context.Background(), "tester", SettingsInput{
		Protocol: strPtr("grpc")}); err == nil {
		t.Fatal("非法协议应拒")
	}
	// 向后兼容:存量行 Protocol 空(018 迁移前的老库行)→ 默认档
	meta.settings.Protocol = ""
	cfg, _ = svc.resolveConfig(context.Background())
	if cfg.Protocol != ProtocolOpenAICompat {
		t.Fatalf("存量空协议应回默认: %+v", cfg)
	}
	// env 覆盖 + 非法 env 如实拒
	svc2, _, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{
		"FENGTU_AI_SECRET":   "test-secret",
		"FENGTU_AI_PROTOCOL": "anthropic",
	})
	cfg, err = svc2.resolveConfig(context.Background())
	if err != nil || cfg.Protocol != ProtocolAnthropic {
		t.Fatalf("env 协议覆盖不符: %+v %v", cfg, err)
	}
	svc3, _, _, _, _ := testServiceEnv(t, &mockProvider{}, map[string]string{
		"FENGTU_AI_SECRET":   "test-secret",
		"FENGTU_AI_PROTOCOL": "grpc",
	})
	if _, err := svc3.resolveConfig(context.Background()); err == nil {
		t.Fatal("非法 env 协议应如实拒")
	}
}

func intPtr(n int) *int { return &n }

func strPtr(s string) *string { return &s }
