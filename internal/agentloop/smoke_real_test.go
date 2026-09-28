// 真实厂商冒烟探针(默认跳过;设 FENGTU_AI_API_KEY 才跑——不烧 CI 钱,
// 台架/排障时手动开)。跑真 provider 的 drive 全链:工具调用→文本→token 账。
package agentloop

import (
	"context"
	"os"
	"strings"
	"testing"
)

func TestRealProviderSmoke(t *testing.T) {
	if os.Getenv("FENGTU_AI_API_KEY") == "" {
		t.Skip("FENGTU_AI_API_KEY 未设,跳过真实厂商冒烟(默认不烧真钱)")
	}
	// NewProvider=nil → 真 llm.NewProvider;Meta/Events/Review 全 fake
	svc, meta, _, _, _ := testServiceEnv(t, nil, map[string]string{
		"FENGTU_AI_API_KEY":  os.Getenv("FENGTU_AI_API_KEY"),
		"FENGTU_AI_BASE_URL": os.Getenv("FENGTU_AI_BASE_URL"),
		"FENGTU_AI_MODEL":    os.Getenv("FENGTU_AI_MODEL"),
		"FENGTU_AI_OUTBOUND": "true",
	})
	svc.deps.NewProvider = nil
	sess, err := svc.CreateSession(context.Background(), "case-1", "smoke")
	if err != nil {
		t.Fatal(err)
	}
	ch, err := svc.Run(context.Background(), sess.ID, "列一下案件里有什么源")
	if err != nil {
		t.Fatal(err)
	}
	var text strings.Builder
	n := 0
	for ev := range ch {
		n++
		t.Logf("EV%d kind=%s tool=%s err=%s reason=%s", n, ev.Kind, ev.ToolName, ev.ErrText, ev.Reason)
		if ev.Kind == "text" || ev.Kind == "result" {
			text.WriteString(ev.Text)
		}
	}
	if n == 0 {
		t.Fatal("零事件——drive 静默收尾,必查")
	}
	got, _ := meta.GetAISession(context.Background(), sess.ID)
	t.Logf("token in=%d out=%d", got.TokensIn, got.TokensOut)
}
