// 上传会话隔离焊死(M4):同一 Manager 两会话交错传块,chunks 目录按
// 会话 id 天然隔离;Complete 各回各的字节流,cleanup 各清各的暂存。
package ingress

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentSessionsIsolated(t *testing.T) {
	dir := t.TempDir()
	m, err := OpenManager(filepath.Join(dir, "up"), 4) // 4 字节块逼出多块
	if err != nil {
		t.Fatalf("管理器打开失败: %v", err)
	}
	contentA := []byte("alpha-会话A-内容-0123456789")
	contentB := []byte("beta--会话B-内容-9876543210!!")
	shaA := shaOfBytes(contentA)
	shaB := shaOfBytes(contentB)

	metaA, err := m.Init("case-x", "a.log", int64(len(contentA)), shaA, "", "", "", "alice")
	if err != nil {
		t.Fatalf("会话 A 开账失败: %v", err)
	}
	metaB, err := m.Init("case-x", "b.log", int64(len(contentB)), shaB, "", "", "", "bob")
	if err != nil {
		t.Fatalf("会话 B 开账失败: %v", err)
	}
	// 目录隔离:会话 id 随机 16 字节,目录必不同
	if m.dirOf(metaA.ID) == m.dirOf(metaB.ID) {
		t.Fatal("两会话暂存目录撞车")
	}
	if metaA.Actor != "alice" || metaB.Actor != "bob" {
		t.Fatalf("Actor 账不符: %s %s", metaA.Actor, metaB.Actor)
	}

	// 交错传块:同一块号两会话并发,块序两会话相反——最容易暴露串味
	totalA := m.chunkCount(metaA)
	totalB := m.chunkCount(metaB)
	put := func(meta *UploadMeta, content []byte, total int) error {
		for i := 0; i < total; i++ {
			end := (i + 1) * int(m.chunkSize)
			if end > len(content) {
				end = len(content)
			}
			if err := m.PutChunk(meta.ID, i,
				bytes.NewReader(content[i*int(m.chunkSize):end]), ""); err != nil {
				return fmt.Errorf("会话 %s 块 %d: %w", meta.ID, i, err)
			}
		}
		return nil
	}
	var wg sync.WaitGroup
	errs := make([]error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errs[0] = put(metaA, contentA, totalA) }()
	go func() { defer wg.Done(); errs[1] = put(metaB, contentB, totalB) }()
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("传块失败(%d): %v", i, err)
		}
	}

	// Complete 各回各的字节流(读全比对)
	for i, tc := range []struct {
		meta    *UploadMeta
		content []byte
	}{{metaA, contentA}, {metaB, contentB}} {
		meta, rc, cleanup, err := m.Complete(tc.meta.ID)
		if err != nil {
			t.Fatalf("Complete(%d) 失败: %v", i, err)
		}
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Fatalf("读流(%d) 失败: %v", i, err)
		}
		if !bytes.Equal(got, tc.content) {
			t.Fatalf("会话 %d 字节流串味: 得 %q", i, got)
		}
		if meta.Filename != tc.meta.Filename || meta.SHA256 != tc.meta.SHA256 {
			t.Fatalf("会话 %d 元数据串味: %+v", i, meta)
		}
		cleanup()
		if _, err := os.Stat(m.dirOf(tc.meta.ID)); !os.IsNotExist(err) {
			t.Fatalf("会话 %d cleanup 后暂存目录应清除", i)
		}
	}
	// 会话账已清:再 Complete 应报无此会话
	if _, _, _, err := m.Complete(metaA.ID); err == nil {
		t.Fatal("cleanup 后再 Complete 应报无此上传会话")
	}
}
