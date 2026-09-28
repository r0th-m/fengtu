// LinuxSC RecoveredBinaries 登记视图(0.32.0-linuxsc):恢复二进制登记,
// 不解析内容(铁律:证据最小化读取,本体留金库)。
//
// 语义基准 = 树庭 backend/app/parsers/linux_recovered.py(逐函数对照移植)。
// 采集端命名契约(§16):
//   - `pid<PID>_exe_<名称>.bin`:deleted exe 恢复样本;
//   - `pid<PID>_fd<N>_memfd.bin`:memfd 内存文件恢复样本;
//   - `_no_hits.txt`:采集端「无命中」声明(0 命中也是合法结果,不静默)。
//
// 与树庭的刻意差异(如实标注):
//   - 树庭的 artifact_sha256 由摄取层算好经 ctx.sha256 传入;丰图 parser
//     只有 path,自算(读文件失败 = 文件级 fatal,如实返回错误)。
//   - naming_contract 落字符串 "true"/"false"(规则锚定字段走 CH
//     JSONExtractString 宽筛);树庭是原生 bool。
//   - 命名契约外的事件树庭把 pid/kind 等键写 null;丰图缺键语义照抄
//     (键不存在 = 无值,不落 null)。
//
// 快照型:ts 一律不设。
package parsers

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// recoveredBinRe 命名契约(整名锚定):exe 形态组2=名称;memfd 形态
// 组3=fd 号(两组互斥,一组命中另一组为空串)。
var recoveredBinRe = regexp.MustCompile(`^pid(\d+)_(?:exe_(.+)|fd(\d+)_memfd)\.bin$`)

// LinuxRecoveredParser RecoveredBinaries/*.bin。
type LinuxRecoveredParser struct{}

// Records 一文件一条事件;文件哈希自算(见文件头),读失败如实报错。
func (LinuxRecoveredParser) Records(path string) (Stream, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("recovered 样本读取失败: %w", err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256(raw))
	name := filepath.Base(path)
	norm := map[string]any{
		"source":          "recovered_binaries",
		"file":            name,
		"artifact_sha256": sum,
	}
	if m := recoveredBinRe.FindStringSubmatch(name); m != nil {
		norm["pid"] = m[1] // 字符串(树庭同;规则按字符串锚定)
		norm["naming_contract"] = "true"
		if m[2] != "" {
			norm["kind"] = "exe"
			norm["exe_name"] = m[2]
		} else {
			norm["kind"] = "memfd"
			norm["fd"] = m[3] // 字符串(树庭同)
		}
	} else {
		// 命名契约外仍登记(不静默),pid/kind/exe_name/fd 缺键如实
		norm["naming_contract"] = "false"
	}
	return &sliceStream{recs: []model.Record{
		{LineNo: 1, Kind: model.KindEvent, Raw: name, Norm: norm},
	}}, nil
}

// LinuxRecoveredNoHitsParser RecoveredBinaries/_no_hits.txt
// (采集端「无命中」声明)。
type LinuxRecoveredNoHitsParser struct{}

// Records 一条事件;第一个非空 strip 行 → note(没有则不写)。
func (LinuxRecoveredNoHitsParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	note := ""
	for _, line := range lines {
		if s := strings.TrimSpace(line); s != "" {
			note = s
			break
		}
	}
	norm := map[string]any{
		"source": "recovered_binaries",
		"result": "no_hits",
	}
	if note != "" {
		norm["note"] = note
	}
	return &sliceStream{recs: []model.Record{
		{LineNo: 1, Kind: model.KindEvent, Raw: note, Norm: norm},
	}}, nil
}
