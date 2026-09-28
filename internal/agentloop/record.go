// LLM 录制挂钩(切片十,ARTEX llm-records 的应急映射):
// recordingProvider 包在 gatedProvider 外侧,每一次厂商调用
// (Stream/Complete)落一条 llm_records 账。
// 档位(record_mode,平台设置热更,每次调用时取):
//   off=不录;metadata=默认,只记时间/模型/token/耗时/会话+案件锚/成败;
//   full=opt-in,追加 prompt/response 全文(截断上限焊死,防超大上下文撑库)。
// 录制失败如实记日志(OnWarn),永不杀 loop——台账不能让位于主链路。
package agentloop

import (
	"context"
	"encoding/json"
	"iter"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Autumn-27/norma/llm"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
)

// LLMRecorder 录制落库面(store.PG 实现;单测 stub)。
type LLMRecorder interface {
	InsertLLMRecord(ctx context.Context, r *store.LLMRecord) error
}

// 全文录制的截断上限(rune;防超长上下文/回复把单行 TEXT 撑成巨物)。
const recordFullCapRunes = 8000

// recordingProvider 逐次调用录制(档位每次调用时读平台设置,改档即时生效)。
type recordingProvider struct {
	inner   llm.Provider
	sess    *store.AISession
	kind    string // chat|intent(附加 system 段=意图 worker 会话)
	model   string
	rec     LLMRecorder
	mode    func() string     // off|metadata|full;读取失败由调用方给默认
	now     func() time.Time  // nil → time.Now
	onWarn  func(string)      // 录制失败如实记;nil → 丢(测试外不 nil)
}

func (p *recordingProvider) recordMode() string {
	m := p.mode()
	switch m {
	case "off", "metadata", "full":
		return m
	}
	return "metadata" // 未知档位如实按默认(只记元数据),不猜不静默
}

func (p *recordingProvider) warn(msg string) {
	if p.onWarn != nil {
		p.onWarn(msg)
	}
}

// capRunes 截断(全文档专用;截断处如实标尾巴)。
func capRecordRunes(s string) string {
	if utf8.RuneCountInString(s) <= recordFullCapRunes {
		return s
	}
	return string([]rune(s)[:recordFullCapRunes]) + "…(录制截断)"
}

// flush 落一条账(后台 ctx:loop 取消不该丢账;失败 warn 不杀 loop)。
func (p *recordingProvider) flush(start time.Time, usage llm.Usage,
	callErr error, prompt, response string) {

	rec := &store.LLMRecord{
		SessionID:  p.sess.ID,
		CaseID:     p.sess.CaseID,
		Kind:       p.kind,
		Model:      p.model,
		Status:     "ok",
		TokensIn:   int64(usage.InputTokens),
		TokensOut:  int64(usage.OutputTokens),
		DurationMs: p.now().Sub(start).Milliseconds(),
	}
	if callErr != nil {
		rec.Status = "error"
		rec.Err = callErr.Error()
	}
	if p.recordMode() == "full" {
		pr, rs := prompt, response
		rec.Prompt, rec.Response = &pr, &rs
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := p.rec.InsertLLMRecord(ctx, rec); err != nil {
		p.warn("LLM 录制落账失败(如实,主链路不受影响): " + err.Error())
	}
}

func (p *recordingProvider) Stream(ctx context.Context,
	req llm.CompletionRequest) iter.Seq2[llm.StreamEvent, error] {

	if p.rec == nil || p.recordMode() == "off" {
		return p.inner.Stream(ctx, req)
	}
	start := p.now()
	// full 档抓请求快照(messages JSON;system 段是铁律提示词,不录——
	// 它不变且含治理语义,录了是噪音;要查去看代码库)
	prompt := ""
	if p.recordMode() == "full" {
		if b, err := json.Marshal(req.Messages); err == nil {
			prompt = capRecordRunes(string(b))
		}
	}
	inner := p.inner.Stream(ctx, req)
	return func(yield func(llm.StreamEvent, error) bool) {
		var resp strings.Builder
		var usage llm.Usage
		var callErr error
		full := p.recordMode() == "full"
		for ev, err := range inner {
			if err != nil {
				callErr = err
			}
			switch ev.Type {
			case llm.SETextDelta:
				if full {
					resp.WriteString(ev.Text)
				}
			case llm.SEMessageStart, llm.SEMessageDelta:
				if ev.Usage.InputTokens > 0 || ev.Usage.OutputTokens > 0 {
					usage = ev.Usage // 末帧快照覆盖(累计口径,取后不取加)
				}
			}
			if !yield(ev, err) {
				break // 消费侧硬停(预算熔断/abort):已收到部分照样落账
			}
		}
		p.flush(start, usage, callErr, prompt, capRecordRunes(resp.String()))
	}
}

func (p *recordingProvider) Complete(ctx context.Context,
	req llm.CompletionRequest) (llm.Message, string, llm.Usage, error) {

	if p.rec == nil || p.recordMode() == "off" {
		return p.inner.Complete(ctx, req)
	}
	start := p.now()
	msg, stop, usage, err := p.inner.Complete(ctx, req)
	prompt, resp := "", ""
	if p.recordMode() == "full" {
		if b, mErr := json.Marshal(req.Messages); mErr == nil {
			prompt = capRecordRunes(string(b))
		}
		resp = capRecordRunes(msg.Text())
	}
	p.flush(start, usage, err, prompt, resp)
	return msg, stop, usage, err
}
