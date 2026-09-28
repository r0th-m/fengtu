// Package web HTTP API 层(Go 标准库 net/http,不引框架;JSON API + SSE
// 任务进度流)。登录闸:除 /api/health 与 /api/auth/{setup,login} 外
// 全端点要会话;审计锚真人用户名。
package web

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// Task 一个异步任务(摄入/扫描)的对账快照。
type Task struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"` // ingest | scan
	CaseID     string     `json:"case_id,omitempty"` // 关联案件(删案在跑闸用;0.18.0 起)
	Status     string     `json:"status"`            // running | done | failed
	Progress   string     `json:"progress"`
	Detail     any        `json:"detail,omitempty"`
	Err        string     `json:"err,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

func (t *Task) terminal() bool { return t.Status != "running" }

// TaskManager 任务台账(进程内存态;持久账在 PG ingest_jobs/scan_runs——
// 重启后任务列表为空,摄入/扫描结果不受影响,如实标注)。
type TaskManager struct {
	mu    sync.Mutex
	tasks map[string]*Task
	order []string
	subs  map[string]map[chan *Task]bool
}

// NewTaskManager 构造。
func NewTaskManager() *TaskManager {
	return &TaskManager{tasks: map[string]*Task{}, subs: map[string]map[chan *Task]bool{}}
}

// New 开任务(caseID=关联案件,可空;删案在跑闸据此拦)。
func (tm *TaskManager) New(kind, caseID string) *Task {
	raw := make([]byte, 12)
	_, _ = rand.Read(raw)
	t := &Task{ID: hex.EncodeToString(raw), Kind: kind, CaseID: caseID,
		Status: "running", CreatedAt: time.Now().UTC()}
	tm.mu.Lock()
	tm.tasks[t.ID] = t
	tm.order = append(tm.order, t.ID)
	tm.mu.Unlock()
	return t
}

// RunningForCase 该案在跑任务清单(进程内存态;与 PG 侧 ingest_jobs/
// intent_nodes 的 running 账并列,删案前置闸两处都查,如实列全)。
func (tm *TaskManager) RunningForCase(caseID string) []*Task {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	var out []*Task
	for _, id := range tm.order {
		t := tm.tasks[id]
		if t.CaseID == caseID && !t.terminal() {
			cp := *t
			out = append(out, &cp)
		}
	}
	return out
}

// Get 取快照。
func (tm *TaskManager) Get(id string) (*Task, bool) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	t, ok := tm.tasks[id]
	if !ok {
		return nil, false
	}
	cp := *t
	return &cp, true
}

// List 全部任务(创建序)。
func (tm *TaskManager) List() []*Task {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	out := make([]*Task, 0, len(tm.order))
	for _, id := range tm.order {
		cp := *tm.tasks[id]
		out = append(out, &cp)
	}
	return out
}

// Update 改任务并广播订阅者。
func (tm *TaskManager) Update(id string, fn func(*Task)) {
	tm.mu.Lock()
	t, ok := tm.tasks[id]
	if !ok {
		tm.mu.Unlock()
		return
	}
	fn(t)
	cp := *t
	for ch := range tm.subs[id] {
		select {
		case ch <- &cp:
		default: // 慢订阅者不堵生产者(快照式流,丢帧不丢终态)
		}
	}
	if t.terminal() {
		for ch := range tm.subs[id] {
			close(ch)
		}
		delete(tm.subs, id)
	}
	tm.mu.Unlock()
}

// Progress 改进度摘要。
func (tm *TaskManager) Progress(id, text string) {
	tm.Update(id, func(t *Task) { t.Progress = text })
}

// Finish 收尾(done|failed)。
func (tm *TaskManager) Finish(id, status, errText string, detail any) {
	tm.Update(id, func(t *Task) {
		now := time.Now().UTC()
		t.Status = status
		t.Err = errText
		t.Detail = detail
		t.FinishedAt = &now
	})
}

// Subscribe 订阅任务流(chan 容量 16;终态后关闭)。cancel 退订。
func (tm *TaskManager) Subscribe(id string) (<-chan *Task, func(), bool) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	if _, ok := tm.tasks[id]; !ok {
		return nil, nil, false
	}
	ch := make(chan *Task, 16)
	if tm.subs[id] == nil {
		tm.subs[id] = map[chan *Task]bool{}
	}
	tm.subs[id][ch] = true
	cancel := func() {
		tm.mu.Lock()
		delete(tm.subs[id], ch)
		tm.mu.Unlock()
	}
	return ch, cancel, true
}
