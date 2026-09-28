// LinuxSC RootkitHunt 面解析(0.32.0-linuxsc):Ebury IOC 库 ls -l 清单。
//
// 语义基准 = 树庭 backend/app/parsers/linux_rootkit.py 的 parse_ebury_ioc
// (逐行对照移植;只含 linux_ebury_ioc 一个 parser,rpm -Va/dpkg -V/
// bpftool 等其余 RootkitHunt parser 不在本切片)。
//
// 与树庭的刻意差异(如实标注):
//   - is_symlink 落字符串 "true"/"false"(规则锚定字段走 CH
//     JSONExtractString 宽筛,只认字符串);树庭是原生 bool。
//
// 快照型:ls -l 行内日期不作事件时间(中文月名 locale 随采集机变,
// 不作为时间锚),ts 一律不设。
package parsers

import (
	"regexp"
	"strings"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// eburyLsLineRe ls -l 行:`-rw-r--r-- 1 root root 22448 2月  11  2020
// /path [-> target]`。日期列是本地化月名(中文「7月」/英文 "Jul" 都
// 出现过),不按日期列逐段解析——树庭契约是非贪婪回溯取最后两个 token:
// 组5=倒数第二 token(丢弃),组6=最后 token=path,组7=symlink 目标
// (可无)。RE2 无回溯引用,此正则可直接用。
var eburyLsLineRe = regexp.MustCompile(
	`^([dl-][rwx-]{9})\S*\s+\d+\s+(\S+)\s+(\S+)\s+(\d+)\s+.*?(\S+)\s+(\S+)(?:\s+->\s+(\S+))?$`)

// LinuxEburyIOCParser RootkitHunt/ebury_ioc_libs.txt。
type LinuxEburyIOCParser struct{}

// Records 逐行解析;空文件 = 0 事件,合法(IOC 未命中,不当作失败)。
func (LinuxEburyIOCParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("空行")})
			continue
		}
		if strings.HasPrefix(s, "total") || strings.HasPrefix(s, "总用量") {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("total 统计行")})
			continue
		}
		m := eburyLsLineRe.FindStringSubmatch(s)
		if m == nil {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("非 ls -l 行")})
			continue
		}
		// m[3]=group、m[5]=倒数第二 token,按契约捕获但不用(照树庭)
		isSymlink := "false"
		if strings.HasPrefix(m[1], "l") {
			isSymlink = "true" // 规则锚定字段落字符串(树庭是 bool)
		}
		norm := map[string]any{
			"source":     "ebury_ioc_libs",
			"mode":       m[1],
			"owner":      m[2],
			"size":       m[4], // 字符串(对齐 ls 原样;树庭同)
			"path":       m[6],
			"is_symlink": isSymlink,
		}
		if m[7] != "" {
			norm["link_target"] = m[7]
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}
