// Package ingress 上传接入(DESIGN §3):分块上传 + 断点续传 + SHA256 校验
// (单文件/zip;zip 单层展开登记多源,语义同索图——不递归嵌套压缩包)。
//
// 断点续传账目:进程内存 + 磁盘分块文件。服务重启即清空上传暂存
// (未完成的上传没有任何登记,不是证据;客户端重新 init 即可)——
// 重启可续是后续切片,如实标注。
//
// 完整性链:可选逐块 SHA256(X-Chunk-SHA256)→ 完成时全文件 SHA256
// 对账(写前校验由 vault 再焊一道)→ WinInfoSC 包内 _HASH_MANIFEST.txt
// 逐文件对账(契约失配 = 证据完整性存疑 = 拒收,不静默;默认档
// Mode=DEFAULT_NO_HASH「采集时未哈希」声明如实记 NoHash 放行——
// 采集时刻指纹仅严格档 -Hash 提供,入库时刻指纹恒由本平台计算)。
package ingress

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// DefaultChunkSize 分块大小(8MB)。
const DefaultChunkSize = 8 << 20

// UploadMeta 一次上传的账。
type UploadMeta struct {
	ID        string    `json:"id"`
	CaseName  string    `json:"case_name"`
	Filename  string    `json:"filename"` // 客户端原文件名(纯 base 名)
	Size      int64     `json:"size"`
	SHA256    string    `json:"sha256"`
	Format    string    `json:"format,omitempty"` // 内置格式绑定(text 源)
	Desc      string    `json:"desc,omitempty"`   // desc 名绑定(text 源)
	TZ        string    `json:"tz,omitempty"`     // 源声明时区
	Actor     string    `json:"actor"`
	CreatedAt time.Time `json:"created_at"`
}

type uploadState struct {
	meta   UploadMeta
	chunks map[int]bool
}

// Manager 上传会话管理器。
type Manager struct {
	dir       string
	chunkSize int64
	mu        sync.Mutex
	uploads   map[string]*uploadState
	now       func() time.Time
}

// OpenManager 打开(并清空)上传暂存目录——重启不续,见包注释。
func OpenManager(dir string, chunkSize int64) (*Manager, error) {
	if chunkSize <= 0 {
		chunkSize = DefaultChunkSize
	}
	if err := os.RemoveAll(dir); err != nil {
		return nil, fmt.Errorf("上传暂存清空失败: %w", err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("上传暂存目录创建失败: %w", err)
	}
	return &Manager{
		dir: dir, chunkSize: chunkSize,
		uploads: map[string]*uploadState{}, now: time.Now,
	}, nil
}

// ChunkSize 分块大小(init 响应回给客户端)。
func (m *Manager) ChunkSize() int64 { return m.chunkSize }

func (m *Manager) dirOf(id string) string { return filepath.Join(m.dir, id) }

// Init 开一个上传会话。
func (m *Manager) Init(caseName, filename string, size int64, sha256Sum,
	format, desc, tz, actor string) (*UploadMeta, error) {

	if strings.TrimSpace(caseName) == "" {
		return nil, fmt.Errorf("case_name 必填")
	}
	if filename == "" || filename != filepath.Base(filename) ||
		strings.ContainsAny(filename, `/\`) {
		return nil, fmt.Errorf("filename 须为纯文件名(不得含路径): %q", filename)
	}
	if size <= 0 {
		return nil, fmt.Errorf("size 须 >0")
	}
	if len(sha256Sum) != 64 {
		return nil, fmt.Errorf("sha256 须为 64 位十六进制")
	}
	if _, err := hex.DecodeString(sha256Sum); err != nil {
		return nil, fmt.Errorf("sha256 须为 64 位十六进制: %v", err)
	}
	if format != "" && desc != "" {
		return nil, fmt.Errorf("format 与 desc 二选一")
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("上传 id 生成失败: %w", err)
	}
	meta := UploadMeta{
		ID: hex.EncodeToString(raw), CaseName: caseName, Filename: filename,
		Size: size, SHA256: strings.ToLower(sha256Sum),
		Format: format, Desc: desc, TZ: tz, Actor: actor,
		CreatedAt: m.now(),
	}
	if err := os.MkdirAll(m.dirOf(meta.ID), 0o755); err != nil {
		return nil, fmt.Errorf("上传目录创建失败: %w", err)
	}
	m.mu.Lock()
	m.uploads[meta.ID] = &uploadState{meta: meta, chunks: map[int]bool{}}
	m.mu.Unlock()
	return &meta, nil
}

func (m *Manager) chunkCount(meta *UploadMeta) int {
	return int((meta.Size + m.chunkSize - 1) / m.chunkSize)
}

// Status 续传账:已收分块清单(客户端据此补传缺口)。
func (m *Manager) Status(id string) (*UploadMeta, []int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st, ok := m.uploads[id]
	if !ok {
		return nil, nil, fmt.Errorf("无此上传会话: %s", id)
	}
	var got []int
	for i := range st.chunks {
		got = append(got, i)
	}
	sort.Ints(got)
	meta := st.meta
	return &meta, got, nil
}

// PutChunk 收一个分块(index 0 起;大小必须 = chunkSize,末块 = 余量;
// chunkSHA 非空则逐块校验)。重复传同一块 = 重传覆盖(续传幂等)。
func (m *Manager) PutChunk(id string, index int, r io.Reader, chunkSHA string) error {
	m.mu.Lock()
	st, ok := m.uploads[id]
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("无此上传会话: %s", id)
	}
	total := m.chunkCount(&st.meta)
	if index < 0 || index >= total {
		return fmt.Errorf("分块序号越界: %d(共 %d 块)", index, total)
	}
	want := m.chunkSize
	if index == total-1 {
		want = st.meta.Size - int64(index)*m.chunkSize
	}

	tmp := filepath.Join(m.dirOf(id), fmt.Sprintf("chunk-%d.tmp", index))
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("分块文件创建失败: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), r)
	if err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("分块写入失败: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("分块收尾失败: %w", err)
	}
	if n != want {
		os.Remove(tmp)
		return fmt.Errorf("分块 %d 大小不符: 期望 %d 字节,实收 %d", index, want, n)
	}
	if chunkSHA != "" {
		if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, chunkSHA) {
			os.Remove(tmp)
			return fmt.Errorf("分块 %d 逐块校验不过: 期望 %s,实算 %s",
				index, chunkSHA, got)
		}
	}
	final := filepath.Join(m.dirOf(id), fmt.Sprintf("chunk-%d", index))
	if err := os.Rename(tmp, final); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("分块落位失败: %w", err)
	}
	m.mu.Lock()
	st.chunks[index] = true
	m.mu.Unlock()
	return nil
}

// Complete 齐块对账:返回全文件流(顺序拼接,不落中间文件)与清理函数。
// 调用方负责:流 → 金库(写前校验全文件 SHA256)→ 登记 → 触发摄入,
// 完成后调 cleanup 清暂存。齐块判定在此,哈希对账在金库写侧。
func (m *Manager) Complete(id string) (*UploadMeta, io.ReadCloser, func(), error) {
	m.mu.Lock()
	st, ok := m.uploads[id]
	m.mu.Unlock()
	if !ok {
		return nil, nil, nil, fmt.Errorf("无此上传会话: %s", id)
	}
	total := m.chunkCount(&st.meta)
	for i := 0; i < total; i++ {
		if !st.chunks[i] {
			return nil, nil, nil, fmt.Errorf("分块不全: 缺第 %d 块(共 %d 块)", i, total)
		}
	}
	files := make([]io.ReadCloser, 0, total)
	for i := 0; i < total; i++ {
		f, err := os.Open(filepath.Join(m.dirOf(id), fmt.Sprintf("chunk-%d", i)))
		if err != nil {
			for _, of := range files {
				of.Close()
			}
			return nil, nil, nil, fmt.Errorf("分块 %d 读取失败: %w", i, err)
		}
		files = append(files, f)
	}
	readers := make([]io.Reader, len(files))
	for i, f := range files {
		readers[i] = f
	}
	meta := st.meta
	cleanup := func() {
		for _, f := range files {
			f.Close()
		}
		m.mu.Lock()
		delete(m.uploads, id)
		m.mu.Unlock()
		_ = os.RemoveAll(m.dirOf(id))
	}
	return &meta, struct {
		io.Reader
		io.Closer
	}{io.MultiReader(readers...), multiCloser(files)}, cleanup, nil
}

type multiCloser []io.ReadCloser

func (mc multiCloser) Close() error {
	for _, c := range mc {
		c.Close()
	}
	return nil
}
