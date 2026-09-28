// Package audit 审计哈希链(DESIGN §5/§9,索图 audit_log 语义移植):
//
//	每条记录 entry_hash = sha256(seq ‖ case_id ‖ ts ‖ actor ‖ action ‖
//	scope ‖ detail_json ‖ prev_hash),prev_hash 链接前一条——
//	篡改任何一条,其后全链对账不过。
//
// 追加侧的原子性(读末哈希 + 写新条必须同事务且全库串行)由 Store
// 实现保证:PG 侧 advisory xact lock(索图 _APPEND_LOCK 竞态教训)。
// 本包只含纯逻辑:哈希计算与全链校验,单测焊死。
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Genesis 创世前哈希(首条的 prev_hash)。
const Genesis = "GENESIS"

// Entry 一条审计记录。
type Entry struct {
	Seq        int64
	CaseID     string // 空 = 无案件上下文(登录/首启等)
	TS         time.Time
	Actor      string
	Action     string
	Scope      string
	DetailJSON string // canonical JSON(键序固定)或空
	PrevHash   string
	EntryHash  string
}

// hashFields 计算 entry_hash(字段间 \x00 分隔,消歧义)。
func hashFields(seq int64, caseID string, ts time.Time, actor, action,
	scope, detailJSON, prevHash string) string {
	h := sha256.New()
	// RFC3339Nano UTC 定死时间呈现,不给时区表示差异留门
	parts := []string{
		fmt.Sprintf("%d", seq), caseID, ts.UTC().Format(time.RFC3339Nano),
		actor, action, scope, detailJSON, prevHash,
	}
	h.Write([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h.Sum(nil))
}

// ComputeHash 供 Store 实现侧追加时计算 entry_hash。
func ComputeHash(seq int64, caseID string, ts time.Time, actor, action,
	scope, detailJSON, prevHash string) string {
	return hashFields(seq, caseID, ts, actor, action, scope, detailJSON, prevHash)
}

// VerifyChain 全链重算校验(按 seq 序)。返回错误即链断/篡改,如实报位置。
func VerifyChain(entries []Entry) error {
	prev := Genesis
	for i, e := range entries {
		if i > 0 && e.Seq <= entries[i-1].Seq {
			return fmt.Errorf("审计链 seq 非递增: 第 %d 条 seq=%d", i+1, e.Seq)
		}
		if e.PrevHash != prev {
			return fmt.Errorf("审计链断于 seq=%d: prev_hash 不符", e.Seq)
		}
		want := hashFields(e.Seq, e.CaseID, e.TS, e.Actor, e.Action,
			e.Scope, e.DetailJSON, e.PrevHash)
		if e.EntryHash != want {
			return fmt.Errorf("审计链篡改于 seq=%d: entry_hash 重算不符", e.Seq)
		}
		prev = e.EntryHash
	}
	return nil
}
