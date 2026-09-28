// LinuxSC SystemInfo 账户面解析(0.32.0-linuxsc):etc/passwd / etc/group。
//
// 语义基准 = 树庭 backend/app/parsers/linux_system.py 的 parse_passwd /
// parse_group(逐行对照移植;os-release/uname/hostnamectl/dmesg 等其余
// SystemInfo parser 不在本切片)。
//
// 与树庭的刻意差异(如实标注):
//   - uid/gid 落字符串(树庭也是字符串,规则按字符串锚定,无差异);
//   - passwd 事件双写 account=username:account 是丰图主机统一面字段
//     (对齐 Windows 侧账户事件的锚定键),树庭靠 emit_account 写账户面;
//   - passwd 派生 empty_password="true"(password_field=="" 时):丰图
//     规则引擎表达不了「等于空串」(子串匹配须非空),树庭规则
//     password_field:"" 的语义由解析器派生承载。
//
// 快照型:ts 一律不设。
package parsers

import (
	"strings"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// LinuxPasswdParser SystemInfo/etc/passwd。
type LinuxPasswdParser struct{}

// Records 冒号分隔契约,恰好 7 段才解析(非 7 段 skip,不硬解——
// 与其余文本 parser 同一取舍)。
func (LinuxPasswdParser) Records(path string) (Stream, error) {
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
		if strings.HasPrefix(s, "#") {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("注释行")})
			continue
		}
		parts := strings.Split(s, ":")
		if len(parts) != 7 {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("非 passwd 行,不硬解")})
			continue
		}
		norm := map[string]any{
			"source":         "passwd",
			"username":       parts[0],
			"password_field": parts[1],
			"uid":            parts[2], // 字符串(规则锚定)
			"gid":            parts[3], // 字符串(规则锚定)
			"gecos":          parts[4],
			"home":           parts[5],
			"shell":          parts[6],
			// account 双写:丰图主机统一面字段(见文件头差异标注)
			"account": parts[0],
		}
		if parts[1] == "" {
			// 派生字段:规则引擎表达不了「等于空串」(见文件头)
			norm["empty_password"] = "true"
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}

// LinuxGroupParser SystemInfo/etc/group。
type LinuxGroupParser struct{}

// Records 冒号分隔契约,恰好 4 段才解析;members 逗号切滤空,有才写。
func (LinuxGroupParser) Records(path string) (Stream, error) {
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
		if strings.HasPrefix(s, "#") {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("注释行")})
			continue
		}
		parts := strings.Split(s, ":")
		if len(parts) != 4 {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("非 group 行,不硬解")})
			continue
		}
		norm := map[string]any{
			"source": "group",
			"group":  parts[0],
			"gid":    parts[2], // 字符串(规则锚定)
		}
		var members []string
		for _, m := range strings.Split(parts[3], ",") {
			if m != "" {
				members = append(members, m)
			}
		}
		if len(members) > 0 {
			norm["members"] = members
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}
