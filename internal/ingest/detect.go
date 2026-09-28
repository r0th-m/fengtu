// 文件类别识别与路由(DESIGN §4.1「识别文件类型 → 路由」)。
//
// 类别判定只看文件名/扩展名(结构信息),不窥内容、不猜:
//   - .evtx            → evtx(纯 Go 原生解析 Velocidex/evtx,见 evtx.go 头部注释)
//   - .log/.txt/.out   → text(行式文本,须由调用方绑定 desc/内置格式才解析;
//     无绑定时是「可解析但缺描述」,如实报错而不是默默登记)
//   - 其余              → raw(原文登记不解析:二进制、镜像、未知格式)
package ingest

import (
	"io"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Kind 文件类别。
type Kind string

const (
	KindText Kind = "text"
	KindEVTX Kind = "evtx"
	// KindNative 树庭面原生解析的二进制/结构源(M3:registry hive/MFT/
	// Prefetch/lnk/USN CSV;包摄入时即解析,语义近 evtx:非行式文本,
	// 行号回查不适用)
	KindNative Kind = "native"
	KindRaw    Kind = "raw"
)

// DetectKind 按扩展名分类(纯函数,零 IO)。
func DetectKind(path string) Kind {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".evtx":
		return KindEVTX
	case ".log", ".txt", ".out":
		return KindText
	default:
		return KindRaw
	}
}

// SniffText 内容嗅探「是否行式文本」(raw 兜底源的金库回查门禁用:
// 扩展名没进入 .txt/.log/.out 白名单的文本——勒索信 *.readme、无扩展名
// 计划任务 XML 等——不应因后缀生僻被锁死;2026-09-23 真实案件
// 实战挖出)。
//
// 判据(前 8KB,结构特征不猜语义):
//   - UTF-8/UTF-16 BOM → 文本;
//   - 含 NUL → 二进制;
//   - 控制字符(\t\r\n 除外)占比 >1% → 二进制;
//   - 其余(含空文件)→ 文本。
func SniffText(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, fmt.Errorf("嗅探打开失败: %w", err)
	}
	defer f.Close()
	var buf [8192]byte
	n, err := f.Read(buf[:])
	if err != nil && n == 0 && err != io.EOF {
		return false, fmt.Errorf("嗅探读取失败: %w", err)
	}
	b := buf[:n]
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return true, nil // UTF-8 BOM
	}
	if len(b) >= 2 && ((b[0] == 0xFF && b[1] == 0xFE) || (b[0] == 0xFE && b[1] == 0xFF)) {
		return true, nil // UTF-16 LE/BE BOM
	}
	ctrl := 0
	for _, c := range b {
		if c == 0 {
			return false, nil // NUL = 二进制铁证
		}
		if c < 0x20 && c != '\t' && c != '\r' && c != '\n' {
			ctrl++
		}
	}
	return n == 0 || float64(ctrl)/float64(n) <= 0.01, nil
}
