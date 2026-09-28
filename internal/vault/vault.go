// Package vault 原文只读金库(DESIGN §5,纪律从 v1 不变):
//
//	data/vault/<sha256 前2位>/<sha256>   —— 内容寻址,只读,证据链锚点
//
// 纪律:
//   - 写前校验:Put 流式落临时文件同时算哈希,与期望 sha256 不符即删拒收,
//     不入库;写入成功后 chmod 只读,临时文件 rename 落位(同盘原子);
//   - 读前校验(AGENTS「读前校验由 vault 切片补」):进程内首次 Open
//     重算哈希对账,通过后记进已验集(只读文件 + 本进程独占目录,
//     重复全量哈希是浪费);显式 Verify 随时可强制重算;
//   - 幂等:同 sha256 重复 Put = 同一证据,对账已在库内容后直接返回。
package vault

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Vault 金库(root 为金库根目录,如 data/vault)。
type Vault struct {
	root string

	mu       sync.Mutex
	verified map[string]bool // 本进程已验集(读前校验一次)
}

// Open 打开(必要时创建)金库。
func Open(root string) (*Vault, error) {
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("金库目录创建失败: %w", err)
	}
	return &Vault{root: root, verified: map[string]bool{}}, nil
}

// Path 内容寻址路径(不校验存在性)。
func (v *Vault) Path(sum string) string {
	return filepath.Join(v.root, sum[:2], sum)
}

// Exists 该哈希是否已在库。
func (v *Vault) Exists(sum string) bool {
	_, err := os.Stat(v.Path(sum))
	return err == nil
}

// Put 流式写入金库(写前校验:边写边算,哈希不符删了拒收)。
// 返回实际字节数。同 sha256 已在库 → 对账后直接返回(幂等)。
func (v *Vault) Put(expectedSHA256 string, r io.Reader) (int64, error) {
	if len(expectedSHA256) != 64 {
		return 0, fmt.Errorf("sha256 须为 64 位十六进制: %q", expectedSHA256)
	}
	if v.Exists(expectedSHA256) {
		if err := v.Verify(expectedSHA256); err != nil {
			return 0, err
		}
		var size int64
		if st, err := os.Stat(v.Path(expectedSHA256)); err == nil {
			size = st.Size()
		}
		// 已在库且对账通过:丢弃流入(调用方语义是「确保在库」)
		if _, err := io.Copy(io.Discard, r); err != nil {
			return 0, fmt.Errorf("幂等检查读流失败: %w", err)
		}
		return size, nil
	}

	tmp, err := os.CreateTemp(v.root, ".tmp-*")
	if err != nil {
		return 0, fmt.Errorf("金库临时文件创建失败: %w", err)
	}
	tmpName := tmp.Name()
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), r)
	if err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return 0, fmt.Errorf("金库写入失败: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("金库临时文件收尾失败: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != expectedSHA256 {
		os.Remove(tmpName)
		return 0, fmt.Errorf("写前校验不过: 期望 sha256 %s,实算 %s,拒收入库",
			expectedSHA256, got)
	}

	dst := v.Path(expectedSHA256)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("金库分桶目录创建失败: %w", err)
	}
	// 先只读再落位:rename 后即为只读证据
	if err := os.Chmod(tmpName, 0o444); err != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("金库只读位设置失败: %w", err)
	}
	if err := os.Rename(tmpName, dst); err != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("金库落位失败: %w", err)
	}
	v.mu.Lock()
	v.verified[expectedSHA256] = true
	v.mu.Unlock()
	return size, nil
}

// Verify 强制重算哈希对账(读前校验的显式形态)。
func (v *Vault) Verify(sum string) error {
	f, err := os.Open(v.Path(sum))
	if err != nil {
		return fmt.Errorf("金库原文打开失败(%s…): %w", sum[:12], err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fmt.Errorf("金库对账读失败(%s…): %w", sum[:12], err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sum {
		return fmt.Errorf("金库对账不过: 寻址 %s,实算 %s——证据完整性存疑,如实报",
			sum[:12], got[:12])
	}
	v.mu.Lock()
	v.verified[sum] = true
	v.mu.Unlock()
	return nil
}

// Remove 删除金库原件(0.18.0 案件删除级联专用;调用方必须先确认全库
// 再无源引用该哈希——内容寻址下其他案件可能共享同一证据,引用仍在的
// 一律不删)。先摘除只读位再删(0444 证据文件);分桶目录空了顺手收,
// 非空留着(其他案件的同桶证据还在)。
func (v *Vault) Remove(sum string) error {
	p := v.Path(sum)
	if err := os.Chmod(p, 0o644); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("金库原件解除只读失败(%s…): %w", sum[:12], err)
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("金库原件删除失败(%s…): %w", sum[:12], err)
	}
	v.mu.Lock()
	delete(v.verified, sum)
	v.mu.Unlock()
	_ = os.Remove(filepath.Dir(p)) // 非空目录 Remove 报错即留,如实不管
	return nil
}

// Open 只读打开(读前校验:本进程首次读重算哈希对账,已验集命中直接开)。
func (v *Vault) OpenFile(sum string) (*os.File, error) {
	v.mu.Lock()
	ok := v.verified[sum]
	v.mu.Unlock()
	if !ok {
		if err := v.Verify(sum); err != nil {
			return nil, err
		}
	}
	f, err := os.Open(v.Path(sum))
	if err != nil {
		return nil, fmt.Errorf("金库原文打开失败(%s…): %w", sum[:12], err)
	}
	return f, nil
}

// Lines 按物理行号区间回查原文([from,to],1 起,闭区间)。
// 行内容按原字节返回(调用方决定编码呈现;GBK 等源如实原样)。
func (v *Vault) Lines(sum string, from, to int) ([]string, error) {
	if from < 1 || to < from {
		return nil, fmt.Errorf("行号区间非法: [%d,%d]", from, to)
	}
	f, err := v.OpenFile(sum)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	lines := make([]string, 0, to-from+1)
	br := bufio.NewReaderSize(f, 1<<20)
	no := 0
	for {
		chunk, rerr := br.ReadBytes('\n')
		if len(chunk) > 0 {
			no++
			if no >= from && no <= to {
				line := chunk
				if line[len(line)-1] == '\n' {
					line = line[:len(line)-1]
				}
				if len(line) > 0 && line[len(line)-1] == '\r' {
					line = line[:len(line)-1]
				}
				lines = append(lines, string(line))
			}
			if no >= to {
				return lines, nil
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return lines, nil
			}
			return nil, fmt.Errorf("金库读行失败: %w", rerr)
		}
	}
}
