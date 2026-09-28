// LinuxSC SSH 面解析(0.32.0-linuxsc):authorized_keys 公钥审查 /
// sshd_config 指令 / sshd -T 生效配置 / ldd 库依赖(Ebury IOC 两档预筛)/
// .ssh 目录权限。
//
// 语义基准 = 树庭 backend/app/parsers/linux_ssh.py(逐函数对照移植)。
// 与树庭的刻意差异(如实标注):
//   - 规则锚定字段一律字符串(is_ioc "true"/"false"、is_dir "true"/"false"):
//     丰图规则宽筛走 ClickHouse JSONExtractString,只认字符串;
//     树庭是原生 bool,此处是序列化形态差异,谓词语义等价。
//   - sshd_config / sshd -T 的 directives 树庭是嵌套 dict;丰图落
//     "key value" 逐行 "\n" join 的 directives_text 字符串(CH 侧好检索),
//     另记 directive_count(键数)。同名指令多次出现在 text 中逐行保序。
//   - 树庭 authorized_keys/ssh_dir_perms 附带 emit_account 写账户面;
//     丰图账户面由 passwd 的 account 字段承载(见 linux_system.go),
//     这里不重复产账户记录。
//   - 密钥本体不落库(密钥材料最小化留存):只留类型/位数/注释/options/
//     blob 的 sha256 指纹与结构风险标,与树庭一致。
//
// 全部快照型:行内无时间戳,ts 一律不设。
package parsers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/ye-mengwen/fengtu/internal/descform"
	"github.com/ye-mengwen/fengtu/internal/model"
)

// ---------------- authorized_keys(LinuxAuthorizedKeysParser) ----------------
// 行格式 `[选项] 类型 base64 [注释]`;属主从路径组件提取(home/<u>/.ssh
// 或 root/.ssh),不硬编码用户。

// authkeyMainRe 行首即密钥类型:`类型 base64 [注释]`。
var authkeyMainRe = regexp.MustCompile(`^(ssh-\S+|ecdsa-\S+|sk-\S+)\s+(\S+)(?:\s+(.*))?$`)

// authkeyFallbackRe 后备:行首是逗号分隔登录选项(from=/command= 等,
// 选项里可含空格/引号),按类型词锚定找「类型 base64 [注释]」。
var authkeyFallbackRe = regexp.MustCompile(`(?:^|\s)((?:ssh|ecdsa|sk)-\S+)\s+(\S+)(?:\s+(.*))?$`)

// nistpBitsRe 从 ecdsa 类型名提取曲线位数(nistp256 等)。
var nistpBitsRe = regexp.MustCompile(`nistp(\d+)`)

// placeholderCommentHosts 占位符注释 host 段(通用知识):keygen 在未命名/
// 模板机上生成的默认注释;真实管理机注释应能对应到具体主机。
var placeholderCommentHosts = map[string]bool{
	"hostname": true, "localhost": true, "localhost.localdomain": true,
	"host": true, "default": true, "test": true, "changeme": true,
}

// weakKeyMaxBits 弱钥阈值:RSA/DSA ≤1024 位(NIST 2013 起停用,通用基线)。
const weakKeyMaxBits = 1024

// sshOwnerFromPath 属主从路径推:路径段含 home/<u>/.ssh → <u>;
// 含 root/.ssh → "root";否则空(不写,不硬猜)。
func sshOwnerFromPath(path string) string {
	seg := strings.FieldsFunc(filepath.ToSlash(path),
		func(r rune) bool { return r == '/' })
	for i := 0; i+1 < len(seg); i++ {
		if seg[i] == "home" && i+2 < len(seg) && seg[i+2] == ".ssh" {
			return seg[i+1]
		}
		if seg[i] == "root" && seg[i+1] == ".ssh" {
			return "root"
		}
	}
	return ""
}

// readWireStr SSH wire format:uint32 BE 长度 + 字节串;越界报错由调用方兜底。
func readWireStr(buf []byte, off int) ([]byte, int, error) {
	if off < 0 || uint64(off)+4 > uint64(len(buf)) {
		return nil, 0, fmt.Errorf("wire string 长度越界(off=%d)", off)
	}
	n := binary.BigEndian.Uint32(buf[off:])
	if uint64(off)+4+uint64(n) > uint64(len(buf)) {
		return nil, 0, fmt.Errorf("wire string 数据越界(off=%d len=%d)", off, n)
	}
	return buf[off+4 : off+4+int(n)], off + 4 + int(n), nil
}

// mpintBits mpint 有效位数(剥前导零填充字节;空 → 0)。
func mpintBits(mpi []byte) int {
	for len(mpi) > 0 && mpi[0] == 0 {
		mpi = mpi[1:]
	}
	if len(mpi) == 0 {
		return 0
	}
	return (len(mpi)-1)*8 + bits.Len8(mpi[0])
}

// sshKeyBits 从公钥 blob 解密钥位数;解不出(未知类型/坏 blob)如实
// ok=false,不落 key_bits。ssh-rsa/ssh-dss 读模数 mpint;ecdsa 按曲线名;
// ed25519/sk 固定位长(树庭对 ssh-ed25519 是 ==,此处前缀匹配是其超集,
// 如实标注;真实类型名不带后缀,两形态等价)。
func sshKeyBits(keyType, blobB64 string) (int, bool) {
	kt := strings.ToLower(keyType)
	if strings.HasPrefix(kt, "ssh-ed25519") || strings.HasPrefix(kt, "sk-ssh-ed25519") {
		return 256, true
	}
	if strings.HasPrefix(kt, "sk-ecdsa-sha2-nistp") || strings.HasPrefix(kt, "ecdsa-sha2-nistp") {
		m := nistpBitsRe.FindStringSubmatch(kt)
		if m == nil {
			return 0, false
		}
		n, err := strconv.Atoi(m[1])
		if err != nil {
			return 0, false
		}
		return n, true
	}
	if kt != "ssh-rsa" && kt != "ssh-dss" {
		return 0, false
	}
	raw, err := base64.StdEncoding.DecodeString(blobB64)
	if err != nil {
		return 0, false // 坏 blob,不硬解
	}
	if _, off, err := readWireStr(raw, 0); err != nil { // string alg
		return 0, false
	} else if kt == "ssh-rsa" {
		if _, off, err = readWireStr(raw, off); err != nil { // string e
			return 0, false
		}
		if n, _, err := readWireStr(raw, off); err != nil { // string n
			return 0, false
		} else {
			return mpintBits(n), true
		}
	}
	// ssh-dss:alg 后第一个 string = p
	_, off, err := readWireStr(raw, 0) // alg
	if err != nil {
		return 0, false
	}
	p, _, err := readWireStr(raw, off) // string p
	if err != nil {
		return 0, false
	}
	return mpintBits(p), true
}

// authkeyRiskFlags 公钥风险标(结构化、通用维度;模糊归因交手册/人):
// weak_key=RSA/DSA ≤1024 位;forced_command=带 command= 限定选项;
// no_comment=无注释;unattributable_comment=注释非 user@host 形态;
// placeholder_comment=注释 host 段是占位符(模板机生成)。按序追加。
func authkeyRiskFlags(keyType string, keyBits int, hasBits bool,
	comment, options string) []string {
	var flags []string
	kt := strings.ToLower(keyType)
	if (strings.HasPrefix(kt, "ssh-rsa") || strings.HasPrefix(kt, "ssh-dss")) &&
		hasBits && keyBits <= weakKeyMaxBits {
		flags = append(flags, "weak_key")
	}
	if options != "" && strings.Contains(strings.ToLower(options), "command=") {
		flags = append(flags, "forced_command")
	}
	if comment == "" {
		flags = append(flags, "no_comment")
	} else if !strings.Contains(comment, "@") {
		flags = append(flags, "unattributable_comment")
	} else {
		host := strings.ToLower(strings.TrimSpace(
			comment[strings.LastIndex(comment, "@")+1:]))
		if placeholderCommentHosts[host] {
			flags = append(flags, "placeholder_comment")
		}
	}
	return flags
}

// LinuxAuthorizedKeysParser SSH/**/.ssh/authorized_keys* 公钥审查。
type LinuxAuthorizedKeysParser struct{}

// Records 逐行解析 authorized_keys;blob_sha256 的哈希对象是 base64
// **字符串** 的 UTF-8 字节(照树庭 sha256(blob.encode())),不是解码后
// 的 wire blob。
func (LinuxAuthorizedKeysParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	owner := sshOwnerFromPath(path)
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
		var keyType, blob, comment, options string
		if m := authkeyMainRe.FindStringSubmatch(s); m != nil {
			keyType, blob, comment = m[1], m[2], m[3]
		} else if idx := authkeyFallbackRe.FindStringSubmatchIndex(s); idx != nil {
			keyType = s[idx[2]:idx[3]]
			blob = s[idx[4]:idx[5]]
			if idx[6] >= 0 {
				comment = s[idx[6]:idx[7]]
			}
			options = strings.TrimSpace(s[:idx[2]]) // 类型词前的行首段
		} else {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("非 authorized_keys 行")})
			continue
		}
		comment = strings.TrimSpace(comment)
		keyBits, hasBits := sshKeyBits(keyType, blob)
		flags := authkeyRiskFlags(keyType, keyBits, hasBits, comment, options)
		norm := map[string]any{
			"source":   "authorized_keys",
			"key_type": keyType,
			// 哈希对象是 base64 字符串本身(见函数头注释)
			"blob_sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(blob))),
		}
		if owner != "" {
			norm["owner"] = owner
		}
		if hasBits {
			norm["key_bits"] = keyBits
		}
		if comment != "" {
			norm["comment"] = comment
		}
		if options != "" { // 主正则命中无 options;后备命中且非空才写
			norm["options"] = options
		}
		if len(flags) > 0 { // 规则锚定:空格串(树庭同形态)
			norm["risk_flags"] = strings.Join(flags, " ")
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}

// ---------------- sshd_config / sshd -T(一文件一条事件) ----------------

// sshdDirectiveRe `Key Value` 或 `Key=Value` 指令。
var sshdDirectiveRe = regexp.MustCompile(`^([A-Za-z0-9]+)\s*[= ]\s*(.*)$`)

// sshdDirectives 同名指令列表化 + 键按首现保序(Go map 无序,检索文本
// 需要确定性输出)。
type sshdDirectives struct {
	keys []string
	vals map[string][]string
}

func (d *sshdDirectives) add(k, v string) {
	if d.vals == nil {
		d.vals = map[string][]string{}
	}
	if _, ok := d.vals[k]; !ok {
		d.keys = append(d.keys, k)
	}
	d.vals[k] = append(d.vals[k], v)
}

func (d *sshdDirectives) count() int { return len(d.keys) }

// text 全部指令按 "key value" 逐行 "\n" join(键按首现序,同名保序)。
func (d *sshdDirectives) text() string {
	var b strings.Builder
	for _, k := range d.keys {
		for _, v := range d.vals[k] {
			b.WriteString(k)
			b.WriteByte(' ')
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// LinuxSshdConfigParser SSH/etc/ssh/sshd_config。
type LinuxSshdConfigParser struct{}

// Records 全文聚合成一条配置事件(Match 块头计数不展开,块内指令照
// 常解析——照树庭;directives 落字符串,见文件头差异标注)。
func (LinuxSshdConfigParser) Records(path string) (Stream, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	enc := "utf-8" // 编码判定与 readLinuxLines 同款:合法 UTF-8 否则 GBK
	if !utf8.Valid(raw) {
		enc = "gbk"
	}
	text, err := descform.DecodeBytes(raw, enc)
	if err != nil {
		return nil, err
	}
	lines := descform.SplitLines(text)

	d := &sshdDirectives{}
	matchBlocks := 0
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
		if strings.HasPrefix(strings.ToLower(s), "match ") {
			matchBlocks++ // 块内条件不展开,如实计数
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("Match 块头(计数不展开)")})
			continue
		}
		if m := sshdDirectiveRe.FindStringSubmatch(s); m != nil {
			d.add(strings.ToLower(m[1]), strings.TrimSpace(m[2]))
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("指令行(已聚合入配置事件)")})
			continue
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
			Raw: line, Reason: strPtrP("非指令行,不硬解")})
	}

	rawText := text
	if utf8.RuneCountInString(text) > 2000 {
		rawText = string([]rune(text)[:2000]) // 前 2000 字符留证
	}
	norm := map[string]any{
		"source":          "sshd_config",
		"directive_count": d.count(),
	}
	if t := d.text(); t != "" {
		norm["directives_text"] = t
	}
	if matchBlocks > 0 {
		norm["match_blocks"] = matchBlocks
	}
	recs = append(recs, model.Record{LineNo: 1, Kind: model.KindEvent,
		Raw: rawText, Norm: norm})
	return &sliceStream{recs: recs}, nil
}

// LinuxSshdEffectiveParser SSH/sshd_T_effective_config.txt(sshd -T
// 生效配置,`key value` 全小写键)。
type LinuxSshdEffectiveParser struct{}

// Records 一条配置事件;按首个空格拆,不足 2 段 skip。
func (LinuxSshdEffectiveParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	d := &sshdDirectives{}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("空行")})
			continue
		}
		k, v, ok := strings.Cut(s, " ") // 按首个空格拆
		if !ok || strings.TrimSpace(v) == "" {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("非 sshd -T 行,不硬解")})
			continue
		}
		d.add(strings.ToLower(k), strings.TrimSpace(v))
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
			Raw: line, Reason: strPtrP("指令行(已聚合入配置事件)")})
	}
	norm := map[string]any{
		"source":          "sshd_T_effective_config",
		"directive_count": d.count(),
	}
	if t := d.text(); t != "" {
		norm["directives_text"] = t
	}
	recs = append(recs, model.Record{LineNo: 1, Kind: model.KindEvent,
		Raw: d.text(), Norm: norm})
	return &sliceStream{recs: recs}, nil
}

// ---------------- ldd sshd 库依赖(Ebury IOC 两档预筛) ----------------

// eburyHardIOCLibs 硬 IOC:Ebury 特有伪装名,合法系统不应出现 → 直通。
var eburyHardIOCLibs = []string{
	"libns2", "libns3", "libns4", "libpw3", "libpw5",
	"libbrnds", "liblinux", "libsem", "libhttpd",
	"libproc", "libmemfs",
}

// eburyAmbiguousIOCLibs 歧义档:RHEL/CentOS 的 sshd 经 krb5 **合法**链接
// libkeyutils,仅当 resolved 落在非标准库目录(替换/劫持迹象)才算命中;
// 标准路径的合法链接保留 ioc_flag 数据但不命中(判断权归人)。
// 诚实边界(照树庭):Ebury 篡改版常原位替换标准路径文件,本层判不出——
// 要靠包校验(rpm -V/dpkg -V)或哈希比对。
var eburyAmbiguousIOCLibs = []string{"libkeyutils"}

// stdLibDirSegs 标准系统库目录(/lib*|/usr/lib* 下;/usr/lib/<multiarch>/
// 由第二段 lib 覆盖)。
var stdLibDirSegs = map[string]bool{
	"lib": true, "lib64": true, "lib32": true, "libx32": true,
}

// isStdLibPath resolved 是否落在标准系统库目录:/lib* 或 /usr/lib*;
// resolved 缺失 → false。
func isStdLibPath(p string) bool {
	if p == "" {
		return false
	}
	segs := strings.Split(p, "/")
	if len(segs) < 3 || segs[0] != "" {
		return false
	}
	if stdLibDirSegs[segs[1]] {
		return true
	}
	return segs[1] == "usr" && len(segs) >= 4 && stdLibDirSegs[segs[2]]
}

// lddLineRe ldd 行:库名 [=> 解析路径] [(0x地址)];vdso 行无解析路径
// (其 `(0x...)` 会被 resolved 贪婪捕获,与树庭同一正则同一行为,照抄)。
var lddLineRe = regexp.MustCompile(
	`^\s*(\S+)(?:\s+=>\s+(\S+)|\s+=>\s+)?\s*(\(0x[0-9a-fA-F]+\))?\s*$`)

// LinuxSshdLibsParser SSH/ldd_sshd.txt。
type LinuxSshdLibsParser struct{}

// Records 每行都产事件(合法 libkeyutils 也入库,is_ioc="false"——
// 宽筛要能看到全貌;is_ioc 是字符串,见文件头差异标注)。
func (LinuxSshdLibsParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		if strings.TrimSpace(line) == "" {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("空行")})
			continue
		}
		s := strings.TrimRight(line, " \t\r")
		m := lddLineRe.FindStringSubmatch(s)
		if m == nil {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("非 ldd 行,不硬解")})
			continue
		}
		lib, resolved, addr := m[1], m[2], m[3]
		probe := strings.ToLower(lib + " " + resolved)
		hard, amb := "", ""
		for _, n := range eburyHardIOCLibs { // 按序 first-match
			if strings.Contains(probe, n) {
				hard = n
				break
			}
		}
		for _, n := range eburyAmbiguousIOCLibs {
			if strings.Contains(probe, n) {
				amb = n
				break
			}
		}
		norm := map[string]any{
			"source": "ldd_sshd",
			"lib":    lib,
		}
		if resolved != "" {
			norm["resolved"] = resolved
		}
		if addr != "" {
			norm["addr"] = addr
		}
		isIOC := false
		if hard != "" {
			norm["ioc_flag"] = hard
			norm["ioc_tier"] = "hard"
			isIOC = true
		} else if amb != "" {
			norm["ioc_flag"] = amb
			norm["ioc_tier"] = "ambiguous"
			isIOC = !isStdLibPath(resolved)
		}
		// 规则锚定字段落字符串(CH JSONExtractString 宽筛);树庭是 bool
		if isIOC {
			norm["is_ioc"] = "true"
		} else {
			norm["is_ioc"] = "false"
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}

// ---------------- .ssh 目录权限(user_ssh_dir_permissions.txt) ----------------

// LinuxSSHDirPermsParser SSH/user_ssh_dir_permissions.txt:
// `===== 目录 =====` 分节 + ls -l 行。
type LinuxSSHDirPermsParser struct{}

// Records 逐行解析;空行/total/总用量/点行 skip。
func (LinuxSSHDirPermsParser) Records(path string) (Stream, error) {
	lines, err := readLinuxLines(path)
	if err != nil {
		return nil, err
	}
	var section string
	var recs []model.Record
	for i, line := range lines {
		no := i + 1
		s := strings.TrimSpace(line)
		if s == "" {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("空行")})
			continue
		}
		if strings.HasPrefix(s, "=====") && strings.HasSuffix(s, "=====") {
			section = strings.Trim(s, "= ")
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("分节行(已记 dir 上下文)")})
			continue
		}
		if strings.HasPrefix(s, "total") || strings.HasPrefix(s, "总用量") {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("total 统计行")})
			continue
		}
		parts := strings.Fields(s)
		if len(parts) < 9 {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("字段不足 9 段,非 ls -l 行")})
			continue
		}
		if name := parts[len(parts)-1]; name == "." || name == ".." {
			recs = append(recs, model.Record{LineNo: no, Kind: model.KindSkip,
				Raw: line, Reason: strPtrP("点行(./..)")})
			continue
		}
		isDir := "false"
		if strings.HasPrefix(parts[0], "d") {
			isDir = "true" // 规则锚定字段落字符串(树庭是 bool)
		}
		norm := map[string]any{
			"source": "user_ssh_dir_permissions",
			"mode":   parts[0],
			"owner":  parts[2],
			"group":  parts[3],
			"size":   parts[4], // 字符串(对齐 ls 原样;树庭同)
			"name":   parts[len(parts)-1],
			"is_dir": isDir,
		}
		if section != "" {
			norm["dir"] = section
		}
		recs = append(recs, model.Record{LineNo: no, Kind: model.KindEvent,
			Raw: line, Norm: norm})
	}
	return &sliceStream{recs: recs}, nil
}
