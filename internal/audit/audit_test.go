// 哈希链纯逻辑焊死:创世/链接/篡改检出/乱序检出。
package audit

import (
	"testing"
	"time"
)

var testTS = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

func buildChain(n int) []Entry {
	entries := make([]Entry, 0, n)
	prev := Genesis
	for i := 1; i <= n; i++ {
		e := Entry{
			Seq:        int64(i),
			CaseID:     "case-1",
			TS:         testTS,
			Actor:      "alice",
			Action:     "test.action",
			Scope:      "scope",
			DetailJSON: `{"k":1}`,
			PrevHash:   prev,
		}
		e.EntryHash = ComputeHash(e.Seq, e.CaseID, e.TS, e.Actor, e.Action,
			e.Scope, e.DetailJSON, e.PrevHash)
		entries = append(entries, e)
		prev = e.EntryHash
	}
	return entries
}

func TestVerifyChainOK(t *testing.T) {
	if err := VerifyChain(buildChain(5)); err != nil {
		t.Fatalf("正常链应校验通过: %v", err)
	}
}

func TestVerifyChainEmpty(t *testing.T) {
	if err := VerifyChain(nil); err != nil {
		t.Fatalf("空链应校验通过: %v", err)
	}
}

func TestVerifyChainTamper(t *testing.T) {
	entries := buildChain(3)
	entries[1].Actor = "mallory" // 篡改中间条
	if err := VerifyChain(entries); err == nil {
		t.Fatal("篡改后应检出 entry_hash 不符")
	}
}

func TestVerifyChainBrokenLink(t *testing.T) {
	entries := buildChain(3)
	entries[2].PrevHash = "deadbeef" // 断链
	if err := VerifyChain(entries); err == nil {
		t.Fatal("断链应检出 prev_hash 不符")
	}
}

func TestComputeHashDeterministic(t *testing.T) {
	a := ComputeHash(1, "c", testTS, "u", "act", "s", "{}", Genesis)
	b := ComputeHash(1, "c", testTS, "u", "act", "s", "{}", Genesis)
	if a != b {
		t.Fatal("同输入哈希必须确定")
	}
	if a == ComputeHash(2, "c", testTS, "u", "act", "s", "{}", Genesis) {
		t.Fatal("seq 变化必须改变哈希")
	}
}
