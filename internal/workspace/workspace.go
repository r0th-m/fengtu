// Package workspace 用户工作区的共享底线(切片十三,案件工作区隔离):
// web 端点(handlers_workspace.go)与 agentloop 只读工具(tools_workspace.go)
// 同一套路径净化 + 内容嗅探,两处不得各写一份(防一边改了一边漏)。
//
// 目录约定:<FENGTU_DATA_DIR>/workspace/<case_id>/... 为案件工作区
// (案件 id 作一级目录);根下不属任何案件的文件是「未分配」遗留区(兼容
// 旧全局工作区,只读可见,不丢用户文件)。与案件原件金库 vault/ 物理隔离
// ——证据链不可断:vault 原件永不进可写通路。
package workspace

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// ErrBadPath 路径非法(逃逸负样本:../、绝对路径、盘符、反斜杠、空段、NUL)。
var ErrBadPath = errors.New(
	"路径非法:必须在工作空间根内(禁 ../、绝对路径、盘符、反斜杠、空段)")

// Resolve 相对路径 → 根内绝对路径。rel 为 slash 分隔相对路径("" = 根)。
// 净化(逐段白名单)+ 二次校验(Rel 必须在根内)+ 符号链接逃逸检查(已存在
// 前缀逐段 Lstat;不存在的尾段放行——upload/mkdir 要创建)。
func Resolve(root, rel string) (string, error) {
	if rel == "" {
		return root, nil
	}
	if strings.ContainsRune(rel, 0) || strings.Contains(rel, "\\") ||
		strings.HasPrefix(rel, "/") || filepath.IsAbs(rel) ||
		(len(rel) >= 2 && rel[1] == ':') {
		return "", ErrBadPath
	}
	parts := strings.Split(rel, "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return "", ErrBadPath
		}
	}
	joined := filepath.Join(append([]string{root}, parts...)...)
	// 二次校验:净化后仍必须在根内(防净化规则未来改动开出逃逸缝)
	relTo, err := filepath.Rel(root, joined)
	if err != nil || relTo == ".." ||
		strings.HasPrefix(relTo, ".."+string(filepath.Separator)) {
		return "", ErrBadPath
	}
	cur := root
	for _, p := range parts {
		cur = filepath.Join(cur, p)
		fi, err := os.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				break // 尾段不存在=待创建,放行
			}
			return "", err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("路径含符号链接,拒绝(防逃逸)")
		}
	}
	return joined, nil
}

// LooksBinary 内容嗅探(不看扩展名):含 NUL 字节,或控制字符
// (除 \t \n \r 外的 <0x20)比例超 30% 即判二进制。
func LooksBinary(b []byte) bool {
	sample := b
	if len(sample) > 8192 {
		sample = sample[:8192]
	}
	if len(sample) == 0 {
		return false
	}
	ctrl := 0
	for _, c := range sample {
		if c == 0 {
			return true
		}
		if c < 0x20 && c != '\t' && c != '\n' && c != '\r' {
			ctrl++
		}
	}
	return ctrl*100 > 30*len(sample)
}
