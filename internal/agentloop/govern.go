// 治理闸:预算熔断(PreToolUse + 消费侧硬停)、外发闸(gatedProvider)、
// 工具调用审计(PostToolUse → 审计哈希链,锚真人+会话)。
package agentloop

import (
	"context"
	"encoding/json"
	"fmt"
	"iter"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/norma/hook"
	"github.com/Autumn-27/norma/llm"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
)

// ---- 预算(两道闸共用的账本) ----

// budget 会话 token 账:KindUsage 事件喂数(消费侧),PreToolUse 熔断
// (第一道)与消费侧硬停(第二道)都读它。输入 token 大头在系统提示词+
// 消息史,真实厂商 usage 是唯一可信口径——拿不到 usage(未返回)时
// 不猜,如实不熔断。
type budget struct {
	limit int64
	in    atomic.Int64
	out   atomic.Int64
}

func newBudget(limit int64) *budget { return &budget{limit: limit} }

func (b *budget) observe(in, out int64) {
	// KindUsage 是累计口径(每轮模型调用后的快照),取大不取加
	for {
		cur := b.in.Load()
		if in <= cur || b.in.CompareAndSwap(cur, in) {
			break
		}
	}
	for {
		cur := b.out.Load()
		if out <= cur || b.out.CompareAndSwap(cur, out) {
			break
		}
	}
}

func (b *budget) exceeded() bool {
	if b.limit <= 0 {
		return false
	}
	return b.in.Load()+b.out.Load() > b.limit
}

func (b *budget) totals() (int64, int64) { return b.in.Load(), b.out.Load() }

// ---- 外发闸(库层) ----

// gatedProvider 外发同意闸的第二刀:任何厂商调用(Stream/Complete)前查闸。
// HTTP 层 403 是第一刀;这刀保证「闸关时一个字节都不出机」不依赖上层记得查。
type gatedProvider struct {
	inner   llm.Provider
	allowed func() bool
}

func (g *gatedProvider) Stream(ctx context.Context, req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {
	if !g.allowed() {
		return func(yield func(llm.StreamEvent, error) bool) {
			yield(llm.StreamEvent{}, ErrOutboundDisabled)
		}
	}
	return g.inner.Stream(ctx, req)
}

func (g *gatedProvider) Complete(ctx context.Context, req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {
	if !g.allowed() {
		return llm.Message{}, "", llm.Usage{}, ErrOutboundDisabled
	}
	return g.inner.Complete(ctx, req)
}

// ---- 工具调用审计 hook ----

// toolRecorder PreToolUse/PostToolUse 配对记录(MaxConcurrency=1 串行执行,
// 栈式配对精确):名/参数/耗时/返回行数/token 快照 → 审计哈希链。
type toolRecorder struct {
	sess  *store.AISession
	audit AuditAppender
	b     *budget
	now   func() time.Time

	mu      sync.Mutex
	pending []pendingCall // 串行执行下长度 ≤1;栈形只为防御
	count   int
}

type pendingCall struct {
	name    string
	input   string // 截断后的参数 JSON
	started time.Time
}

func (s *Service) buildHooks(sess *store.AISession, b *budget) (*hook.Registry, *toolRecorder) {
	rec := &toolRecorder{sess: sess, audit: s.deps.Audit, b: b, now: s.deps.Now}
	reg := hook.NewRegistry()
	reg.On(hook.PreToolUse, rec.pre)
	reg.On(hook.PostToolUse, rec.post)
	return reg, rec
}

// pre 预算熔断(第一道)+ 开计时。
func (r *toolRecorder) pre(_ context.Context, ev hook.Event) hook.Result {
	if r.b.exceeded() {
		in, out := r.b.totals()
		return hook.Result{
			Decision: "block",
			Message: fmt.Sprintf("会话 token 预算熔断: 已用 %d > 预算 %d,工具调用被拒(如实);请收束汇报已有发现",
				in+out, r.b.limit),
		}
	}
	input := string(ev.Input)
	if utf8.RuneCountInString(input) > 500 {
		input = string([]rune(input)[:500]) + "…"
	}
	r.mu.Lock()
	r.pending = append(r.pending, pendingCall{
		name: ev.ToolName, input: input, started: r.now()})
	r.mu.Unlock()
	return hook.Result{}
}

// post 耗时/行数/token 快照进审计链(锚:案件+真人+会话+工具)。
func (r *toolRecorder) post(_ context.Context, ev hook.Event) hook.Result {
	r.mu.Lock()
	var pc pendingCall
	if n := len(r.pending); n > 0 {
		pc = r.pending[n-1]
		r.pending = r.pending[:n-1]
	} else {
		pc = pendingCall{name: ev.ToolName}
	}
	r.count++
	callNo := r.count
	r.mu.Unlock()

	lines := 0
	if len(ev.Result) > 0 {
		// norma PostToolUse 的 Result = json.Marshal(res.Flatten())(JSON 字符串)
		var flat string
		if err := json.Unmarshal(ev.Result, &flat); err == nil {
			lines = countLines(flat)
		} else {
			lines = countLines(string(ev.Result)) // 非预期形态如实按原文计
		}
	}
	in, out := r.b.totals()
	// 审计失败如实记不进链也不该杀 loop——但零静默:进 transcript 可见的
	// 途径没有,选择让工具结果照常返回,审计缺失由 ai.message 汇总账的
	// tool_calls 计数与实际链条目对账可查(如实标注)。
	_, _, _ = r.audit.AppendAudit(context.Background(), r.sess.CaseID,
		r.sess.CreatedBy, "ai.tool_call", r.sess.ID, map[string]any{
			"seq": callNo, "tool": pc.name, "input": pc.input,
			"duration_ms": r.now().Sub(pc.started).Milliseconds(),
			"result_lines": lines, "is_error": ev.IsError,
			"tokens_in": in, "tokens_out": out,
		})
	return hook.Result{}
}

func (r *toolRecorder) calls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.count
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	n := 1
	for _, c := range s {
		if c == '\n' {
			n++
		}
	}
	return n
}
