// LinuxSC SSH 面解析器焊死:authorized_keys(主/后备正则、owner 路径推导、
// RSA/DSS 位数解算、4 类 risk_flags 分支)/ sshd_config / sshd -T /
// ldd Ebury 两档 IOC / .ssh 目录权限,正负样本全覆盖。
package parsers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// writeSSHCase 落测试样本(rel 支持多层目录,模拟采集包 SSH/ 结构)。
func writeSSHCase(t *testing.T, rel, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

// collectSSHRecs 通用:跑 parser 收全量记录。
func collectSSHRecs(t *testing.T, p Parser, path string) []model.Record {
	t.Helper()
	st, err := p.Records(path)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	defer st.Close()
	var out []model.Record
	for {
		rec, ok := st.Next()
		if !ok {
			break
		}
		out = append(out, rec)
	}
	if err := st.Err(); err != nil {
		t.Fatalf("流错误: %v", err)
	}
	return out
}

// sshWireString SSH wire format:uint32 BE 长度 + 字节串。
func sshWireString(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

// rsaTestBlob 按 SSH wire format 合成 ssh-rsa blob(string alg + string e
// + string n),n 顶位置 1(前导 0x00 填充),有效位数恰为 keyBits。
func rsaTestBlob(keyBits int) string {
	n := make([]byte, keyBits/8)
	n[0] = 0x80
	for i := 1; i < len(n); i++ {
		n[i] = byte(i)
	}
	blob := append(sshWireString([]byte("ssh-rsa")),
		sshWireString([]byte{1, 0, 1})...) // e = 65537
	blob = append(blob, sshWireString(
		append([]byte{0x00}, n...))...) // n(mpint 补前导零)
	return base64.StdEncoding.EncodeToString(blob)
}

// dssTestBlob 合成 ssh-dss blob(alg 后第一个 string = p)。
func dssTestBlob(keyBits int) string {
	p := make([]byte, keyBits/8)
	p[0] = 0x80
	blob := append(sshWireString([]byte("ssh-dss")),
		sshWireString(append([]byte{0x00}, p...))...)
	return base64.StdEncoding.EncodeToString(blob)
}

// 正样本 1:主正则行(类型在行首)+ owner 从 home 路径推 + ed25519 固定位长。
func TestLinuxAuthkeysMainLine(t *testing.T) {
	blob := "AAAAC3NzaC1lZDI1NTE5AAAAIEvampleKeyMaterialForTest1234567890abcd"
	path := writeSSHCase(t, "SSH/home/alice/.ssh/authorized_keys",
		"# 注释行跳过\n\nssh-ed25519 "+blob+" alice@laptop\n")
	recs := collectSSHRecs(t, LinuxAuthorizedKeysParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 1 {
		t.Fatalf("事件数 = %d, want 1(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["source"] != "authorized_keys" || e["owner"] != "alice" ||
		e["key_type"] != "ssh-ed25519" || e["comment"] != "alice@laptop" {
		t.Fatalf("主正则字段错: %v", e)
	}
	if e["key_bits"] != 256 {
		t.Fatalf("ed25519 位数 = %v, want 256", e["key_bits"])
	}
	want := fmt.Sprintf("%x", sha256.Sum256([]byte(blob)))
	if e["blob_sha256"] != want {
		t.Fatalf("blob_sha256 = %v, want %v(哈希对象是 base64 字符串)", e["blob_sha256"], want)
	}
	if _, has := e["options"]; has {
		t.Fatalf("主正则命中不应有 options: %v", e)
	}
	if _, has := e["risk_flags"]; has {
		t.Fatalf("干净行不应有 risk_flags: %v", e)
	}
	// 快照型恒无时间
	if evs[0].TsUTC != nil || evs[0].DTLocal != nil {
		t.Fatalf("快照型不应有时间: %+v", evs[0])
	}
	// 行账:注释 + 空行 skip,零静默
	if len(recs) != 3 {
		t.Fatalf("行账 = %d, want 3", len(recs))
	}
}

// 正样本 2:RSA 位数解算(SSH wire format 合成 1024/2048 位 blob)。
func TestLinuxAuthkeysRSABits(t *testing.T) {
	blob1024 := rsaTestBlob(1024)
	blob2048 := rsaTestBlob(2048)
	path := writeSSHCase(t, "SSH/root/.ssh/authorized_keys",
		"ssh-rsa "+blob1024+" weak@office\n"+
			"ssh-rsa "+blob2048+" strong@office\n")
	evs := eventsOf(collectSSHRecs(t, LinuxAuthorizedKeysParser{}, path))
	if len(evs) != 2 {
		t.Fatalf("事件数 = %d, want 2", len(evs))
	}
	if evs[0].Norm["key_bits"] != 1024 {
		t.Fatalf("1024 位 blob 解出 = %v", evs[0].Norm["key_bits"])
	}
	if evs[0].Norm["risk_flags"] != "weak_key" {
		t.Fatalf("1024 位 RSA 应标 weak_key: %v", evs[0].Norm)
	}
	if evs[1].Norm["key_bits"] != 2048 {
		t.Fatalf("2048 位 blob 解出 = %v", evs[1].Norm["key_bits"])
	}
	if _, has := evs[1].Norm["risk_flags"]; has {
		t.Fatalf("2048 位 RSA 不应标 weak_key: %v", evs[1].Norm)
	}
	// root 路径属主
	if evs[0].Norm["owner"] != "root" {
		t.Fatalf("root/.ssh 属主 = %v, want root", evs[0].Norm["owner"])
	}
}

// DSS 位数(alg 后第一个 string = p)+ ecdsa 曲线名提取。
func TestLinuxAuthkeysDSSAndECDSABits(t *testing.T) {
	path := writeSSHCase(t, "SSH/root/.ssh/authorized_keys",
		"ssh-dss "+dssTestBlob(1024)+" old@office\n"+
			"ecdsa-sha2-nistp384 AAAAecdsablob user@host\n")
	evs := eventsOf(collectSSHRecs(t, LinuxAuthorizedKeysParser{}, path))
	if len(evs) != 2 {
		t.Fatalf("事件数 = %d, want 2", len(evs))
	}
	if evs[0].Norm["key_bits"] != 1024 ||
		evs[0].Norm["risk_flags"] != "weak_key" {
		t.Fatalf("DSS 1024 应解出位数并标弱钥: %v", evs[0].Norm)
	}
	if evs[1].Norm["key_bits"] != 384 {
		t.Fatalf("nistp384 应解出 384: %v", evs[1].Norm)
	}
}

// risk_flags 分支:forced_command(后备正则带 options)/ no_comment /
// unattributable_comment / placeholder_comment,且按序 join。
func TestLinuxAuthkeysRiskFlags(t *testing.T) {
	blob2048 := rsaTestBlob(2048)
	blob1024 := rsaTestBlob(1024)
	path := writeSSHCase(t, "SSH/home/backup/.ssh/authorized_keys",
		// 后备正则:行首选项含空格/引号,weak+forced+no_comment 三标按序
		`command="/usr/bin/rsync --server" ssh-rsa `+blob1024+"\n"+
			// 无注释
			"ssh-ed25519 AAAAed25519blob\n"+
			// 注释无 @
			"ssh-rsa "+blob2048+" 值班机备用\n"+
			// 占位符 host 段
			"ssh-rsa "+blob2048+" deploy@localhost.localdomain\n")
	evs := eventsOf(collectSSHRecs(t, LinuxAuthorizedKeysParser{}, path))
	if len(evs) != 4 {
		t.Fatalf("事件数 = %d, want 4", len(evs))
	}
	e := evs[0].Norm
	if e["options"] != `command="/usr/bin/rsync --server"` {
		t.Fatalf("后备正则 options 错: %v", e)
	}
	if e["risk_flags"] != "weak_key forced_command no_comment" {
		t.Fatalf("risk_flags 按序 join 错: %v", e["risk_flags"])
	}
	if evs[1].Norm["risk_flags"] != "no_comment" {
		t.Fatalf("无注释应标 no_comment: %v", evs[1].Norm)
	}
	if evs[2].Norm["risk_flags"] != "unattributable_comment" {
		t.Fatalf("无 @ 注释应标 unattributable: %v", evs[2].Norm)
	}
	if evs[3].Norm["risk_flags"] != "placeholder_comment" {
		t.Fatalf("占位 host 注释应标 placeholder: %v", evs[3].Norm)
	}
}

// 负样本:非密钥行 skip;坏 blob 不硬解(无 key_bits);非 home/root 路径
// 不写 owner。
func TestLinuxAuthkeysNegative(t *testing.T) {
	path := writeSSHCase(t, "SSH/etc/ssh/authorized_keys",
		"这不是密钥行\n"+
			"ssh-rsa !!!not-valid-base64!!! user@x\n")
	recs := collectSSHRecs(t, LinuxAuthorizedKeysParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 1 {
		t.Fatalf("事件数 = %d, want 1(recs=%v)", len(evs), recs)
	}
	if recs[0].Kind != model.KindSkip || recs[0].Reason == nil ||
		*recs[0].Reason != "非 authorized_keys 行" {
		t.Fatalf("垃圾行应 skip 留账: %+v", recs[0])
	}
	e := evs[0].Norm
	if _, has := e["key_bits"]; has {
		t.Fatalf("坏 blob 不应有 key_bits: %v", e)
	}
	if _, has := e["owner"]; has {
		t.Fatalf("etc 路径不应推 owner: %v", e)
	}
	if _, has := e["risk_flags"]; has {
		t.Fatalf("坏 blob 无位数不标弱钥,有 @ 注释无标: %v", e)
	}
}

// sshd_config:Key Value/Key=Value 双写法;同名列表化;Match 块计数不展开
// (块内指令照常解析,照树庭);Raw=全文前 2000 字符。
func TestLinuxSshdConfig(t *testing.T) {
	content := "# 注释\n\nPort 22\nPermitRootLogin=no\n" +
		"ListenAddress 0.0.0.0\nListenAddress ::\n" +
		"Match User admin\n    AllowTcpForwarding no\n"
	path := writeSSHCase(t, "SSH/etc/ssh/sshd_config", content)
	recs := collectSSHRecs(t, LinuxSshdConfigParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 1 {
		t.Fatalf("事件数 = %d, want 1(一文件一条)", len(evs))
	}
	e := evs[0].Norm
	if e["source"] != "sshd_config" || e["directive_count"] != 4 ||
		e["match_blocks"] != 1 {
		t.Fatalf("sshd_config 聚合错: %v", e)
	}
	want := "port 22\npermitrootlogin no\nlistenaddress 0.0.0.0\n" +
		"listenaddress ::\nallowtcpforwarding no"
	if e["directives_text"] != want {
		t.Fatalf("directives_text = %q, want %q", e["directives_text"], want)
	}
	if evs[0].LineNo != 1 || evs[0].Raw != content {
		t.Fatalf("事件应锚 LineNo=1 且 Raw=全文(<2000 字符)")
	}
}

// sshd -T 生效配置:按首个空格拆,不足 2 段 skip。
func TestLinuxSshdEffective(t *testing.T) {
	path := writeSSHCase(t, "SSH/sshd_T_effective_config.txt",
		"port 22\nlistenaddress [::]:22\nlistenaddress 0.0.0.0:22\n"+
			"permitrootlogin yes\nbadlinenospace\n\n")
	recs := collectSSHRecs(t, LinuxSshdEffectiveParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 1 {
		t.Fatalf("事件数 = %d, want 1", len(evs))
	}
	e := evs[0].Norm
	if e["source"] != "sshd_T_effective_config" || e["directive_count"] != 3 {
		t.Fatalf("sshd -T 聚合错: %v", e)
	}
	if !strings.Contains(e["directives_text"].(string),
		"listenaddress [::]:22\nlistenaddress 0.0.0.0:22") {
		t.Fatalf("同名指令应逐行保序: %q", e["directives_text"])
	}
	if _, has := e["match_blocks"]; has {
		t.Fatalf("sshd -T 无 match_blocks: %v", e)
	}
}

// ldd Ebury 预筛三档:hard 直通 / libkeyutils 标准目录不命中 /
// libkeyutils 异常路径命中;每行都产事件。
func TestLinuxSshdLibs(t *testing.T) {
	path := writeSSHCase(t, "SSH/ldd_sshd.txt",
		"\tlinux-vdso.so.1 =>  (0x00007ffd6e5e6000)\n"+
			"\tlibns2.so.2 => /lib64/libns2.so.2 (0x00007f31f8068000)\n"+
			"\tlibkeyutils.so.1 => /lib64/libkeyutils.so.1 (0x00007f31f8068000)\n"+
			"\tlibkeyutils.so.1 => /tmp/evil/libkeyutils.so.1 (0x00007f31f8068000)\n"+
			"\tlibkeyutils.so.1 => /usr/lib/x86_64-linux-gnu/libkeyutils.so.1 (0x00007f31f8068000)\n"+
			"\tlibwrap.so.0 => /lib/x86_64-linux-gnu/libwrap.so.0 (0x00007f31f8068000)\n"+
			"这不是 ldd 行 ((\n")
	recs := collectSSHRecs(t, LinuxSshdLibsParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 6 {
		t.Fatalf("事件数 = %d, want 6(垃圾行 skip)", len(evs))
	}
	// vdso:`(0x...)` 被 resolved 贪婪捕获(树庭同一正则同一行为,照抄)
	if evs[0].Norm["resolved"] != "(0x00007ffd6e5e6000)" ||
		evs[0].Norm["is_ioc"] != "false" {
		t.Fatalf("vdso 行解析错: %v", evs[0].Norm)
	}
	// hard 档直通
	e := evs[1].Norm
	if e["is_ioc"] != "true" || e["ioc_flag"] != "libns2" ||
		e["ioc_tier"] != "hard" || e["resolved"] != "/lib64/libns2.so.2" ||
		e["addr"] != "(0x00007f31f8068000)" {
		t.Fatalf("hard 档错: %v", e)
	}
	// libkeyutils 标准目录(/lib64):保留 ioc_flag 但不命中
	e = evs[2].Norm
	if e["is_ioc"] != "false" || e["ioc_flag"] != "libkeyutils" ||
		e["ioc_tier"] != "ambiguous" {
		t.Fatalf("标准目录 libkeyutils 不应命中: %v", e)
	}
	// libkeyutils 异常路径:命中
	if evs[3].Norm["is_ioc"] != "true" ||
		evs[3].Norm["ioc_tier"] != "ambiguous" {
		t.Fatalf("异常路径 libkeyutils 应命中: %v", evs[3].Norm)
	}
	// /usr/lib/<multiarch>/ 由 p[2]==lib 判标准
	if evs[4].Norm["is_ioc"] != "false" {
		t.Fatalf("/usr/lib/x86_64-linux-gnu 应判标准目录: %v", evs[4].Norm)
	}
	// 干净库:无 ioc_flag,is_ioc 仍落 "false"
	e = evs[5].Norm
	if e["is_ioc"] != "false" {
		t.Fatalf("干净库 is_ioc 应为 \"false\": %v", e)
	}
	if _, has := e["ioc_flag"]; has {
		t.Fatalf("干净库不应有 ioc_flag: %v", e)
	}
}

// .ssh 目录权限:分节 + ls 行;total/点行/字段不足 skip;is_dir 字符串。
func TestLinuxSSHDirPerms(t *testing.T) {
	path := writeSSHCase(t, "SSH/user_ssh_dir_permissions.txt",
		"===== /root =====\n"+
			"总用量 8\n"+
			"drwx------   2 root root 4096 6月   1 21:10 .\n"+
			"drwx------ 2 root root 4096 6月 1 21:10 .ssh\n"+
			"-rw------- 1 root root 0 6月 1 21:10 authorized_keys\n"+
			"===== /home/alice/.ssh =====\n"+
			"-rw------- 1 alice alice 602 6月 1 21:10 authorized_keys\n"+
			"garbage line\n")
	recs := collectSSHRecs(t, LinuxSSHDirPermsParser{}, path)
	evs := eventsOf(recs)
	if len(evs) != 3 {
		t.Fatalf("事件数 = %d, want 3(recs=%v)", len(evs), recs)
	}
	e := evs[0].Norm
	if e["dir"] != "/root" || e["mode"] != "drwx------" ||
		e["owner"] != "root" || e["size"] != "4096" || e["name"] != ".ssh" ||
		e["is_dir"] != "true" {
		t.Fatalf(".ssh 目录行错: %v", e)
	}
	if evs[1].Norm["is_dir"] != "false" || evs[1].Norm["name"] != "authorized_keys" {
		t.Fatalf("文件行错: %v", evs[1].Norm)
	}
	e = evs[2].Norm
	if e["dir"] != "/home/alice/.ssh" || e["owner"] != "alice" ||
		e["group"] != "alice" || e["size"] != "602" {
		t.Fatalf("alice 分节行错: %v", e)
	}
	// 点行/total/垃圾行 skip 留账
	if len(recs) != 8 {
		t.Fatalf("行账 = %d, want 8", len(recs))
	}
}
