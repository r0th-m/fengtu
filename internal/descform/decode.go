// 源文件解码(语义照索图 ingest._iter_lines:
// open(path, encoding=enc, errors="replace") + 通用换行)。
//
//   - encoding 由描述文件声明(缺省 utf-8);GBK 业务日志是常态;
//   - 解码错误与 Python errors="replace" 对齐:非法字节序列替换为
//     U+FFFD(UTF-8 按 Unicode「极大子串」规则逐段替换,与 CPython 同款);
//   - 换行:通用换行语义(\r\n / \n / 裸 \r 都是行界),
//     行尾不含换行符;解析侧的空行判定与索图一致(strip 后为空)。
package descform

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

// LookupEncoding 规范化编码名;支持范围如实(Go 切片只承诺 utf-8/gbk 系)。
func LookupEncoding(enc string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "utf-8", "utf8", "utf_8":
		return "utf-8", true
	case "gbk", "cp936", "gb2312", "gb18030":
		// GBK 是 GB2312 的超集;gb18030 对常见 GBK 字节段兼容,
		// 超出 GBK 的四字节段未实测,如实归属本切片边界
		return "gbk", true
	}
	return "", false
}

// DecodeFile 读文件 → 按声明编码解码(errors=replace 语义)→
// 通用换行切成物理行(不含行尾换行符)。
func DecodeFile(path string, encoding string) ([]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text, err := DecodeBytes(raw, encoding)
	if err != nil {
		return nil, err
	}
	return SplitLines(text), nil
}

// DecodeBytes 字节 → UTF-8 文本;编码未知如实报错(不带病解析)。
func DecodeBytes(raw []byte, encoding string) (string, error) {
	enc, ok := LookupEncoding(encoding)
	if !ok {
		return "", fmt.Errorf("未知编码: %q", encoding)
	}
	switch enc {
	case "utf-8":
		return sanitizeUTF8(raw), nil
	default: // gbk 系
		out, err := io.ReadAll(transform.NewReader(
			bytes.NewReader(raw), simplifiedchinese.GBK.NewDecoder()))
		if err != nil {
			return "", fmt.Errorf("GBK 解码失败: %w", err)
		}
		return string(out), nil
	}
}

// SplitLines 通用换行切分:\r\n / \n / 裸 \r 都是行界,行尾不含换行符。
// 与 Python 文本模式迭代文件的行语义一致(末行无换行也成行;
// 空文件 → 0 行;文件以换行结尾 → 不多空行)。
func SplitLines(text string) []string {
	if text == "" {
		return nil
	}
	// 预分配:\n 计数是上界(裸 \r 行界只会更少realloc;台架 pprof 实测
	// growslice 是热路径,精确容量一次到位)
	lines := make([]string, 0, strings.Count(text, "\n")+1)
	start := 0
	i := 0
	for i < len(text) {
		c := text[i]
		if c == '\n' {
			lines = append(lines, text[start:i])
			i++
			start = i
		} else if c == '\r' {
			lines = append(lines, text[start:i])
			i++
			if i < len(text) && text[i] == '\n' {
				i++
			}
			start = i
		} else {
			i++
		}
	}
	if start < len(text) {
		lines = append(lines, text[start:])
	}
	return lines
}

// sanitizeUTF8 按 CPython errors="replace" 语义清洗:
// 非法序列按「极大子串」规则每段替换为一个 U+FFFD。
func sanitizeUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var out bytes.Buffer
	out.Grow(len(b))
	i := 0
	for i < len(b) {
		c := b[i]
		if c < 0x80 {
			out.WriteByte(c)
			i++
			continue
		}
		size, lo2, hi2 := seqSpec(c)
		if size == 0 {
			// 孤立的延续字节 / C0 C1 / F5..FF:单字节非法
			out.WriteString("�")
			i++
			continue
		}
		k := 1
		for k < size && i+k < len(b) {
			lo, hi := byte(0x80), byte(0xBF)
			if k == 1 {
				lo, hi = lo2, hi2
			}
			if b[i+k] < lo || b[i+k] > hi {
				break
			}
			k++
		}
		if k == size {
			out.Write(b[i : i+size])
			i += size
		} else {
			// 极大子串 = 已匹配的 k 个字节,整体换一个 U+FFFD
			out.WriteString("�")
			i += k
		}
	}
	return out.String()
}

// seqSpec 返回 UTF-8 首字节对应的序列长度与第二字节的合法区间
// (RFC 3629 收窄:E0/ED/F0/F4 的第二字节有特殊范围)。
func seqSpec(c byte) (size int, lo2, hi2 byte) {
	switch {
	case c >= 0xC2 && c <= 0xDF:
		return 2, 0x80, 0xBF
	case c == 0xE0:
		return 3, 0xA0, 0xBF
	case c >= 0xE1 && c <= 0xEC, c == 0xEE, c == 0xEF:
		return 3, 0x80, 0xBF
	case c == 0xED:
		return 3, 0x80, 0x9F
	case c == 0xF0:
		return 4, 0x90, 0xBF
	case c >= 0xF1 && c <= 0xF3:
		return 4, 0x80, 0xBF
	case c == 0xF4:
		return 4, 0x80, 0x8F
	}
	return 0, 0, 0
}
