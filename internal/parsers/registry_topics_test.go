// registry 专题语义(Shimcache/SAM/SECURITY)测试:regf 容器无法手工拼,
// 二进制解码全部走纯字节函数合成正负样本;hive 级用已入库的 Velocidex
// testdata NTUSER.DAT(结构真实、无本专题键 → 全 0 + notes 如实)验管线,
// 并焊死凭据材料纪律(源码级断言不 open 原则性不碰键)。
package parsers

import (
	"encoding/binary"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// u16str 合成 UTF-16LE 字节(ASCII 范围)。
func u16str(s string) []byte {
	b := make([]byte, 0, len(s)*2)
	for _, r := range s {
		var c [2]byte
		binary.LittleEndian.PutUint16(c[:], uint16(r))
		b = append(b, c[:]...)
	}
	return b
}

// buildShimBlob 造 AppCompatCache blob:stats 偏移起逐条目
// (magic+crc32+entry_len 头 + 条目体)。
func buildShimBlob(statsOff int, magic string, bodies [][]byte) []byte {
	blob := make([]byte, statsOff)
	for i, body := range bodies {
		blob = append(blob, []byte(magic)...)
		var h [8]byte
		binary.LittleEndian.PutUint32(h[0:], uint32(0xC0DE0000+i))
		binary.LittleEndian.PutUint32(h[4:], uint32(len(body)))
		blob = append(blob, h[:]...)
		blob = append(blob, body...)
	}
	return blob
}

// shimWin10Body Win10 条目体:path_len u16 + UTF-16LE path + FILETIME 8B。
func shimWin10Body(path string, ft uint64) []byte {
	p := u16str(path)
	b := make([]byte, 0, 2+len(p)+8)
	var c [2]byte
	binary.LittleEndian.PutUint16(c[:], uint16(len(p)))
	b = append(b, c[:]...)
	b = append(b, p...)
	var f [8]byte
	binary.LittleEndian.PutUint64(f[:], ft)
	return append(b, f[:]...)
}

// shimWin8Body Win8/8.1 条目体:path + package_len u16 + package + 5×u32。
func shimWin8Body(path string, flags uint32, ft uint64) []byte {
	p := u16str(path)
	b := make([]byte, 0, 2+len(p)+2+20)
	var c [2]byte
	binary.LittleEndian.PutUint16(c[:], uint16(len(p)))
	b = append(b, c[:]...)
	b = append(b, p...)
	b = append(b, 0, 0) // package_len=0
	var u [20]byte
	binary.LittleEndian.PutUint32(u[0:], flags)
	binary.LittleEndian.PutUint32(u[8:], uint32(ft&0xFFFFFFFF))
	binary.LittleEndian.PutUint32(u[12:], uint32(ft>>32))
	return append(b, u[:]...)
}

func TestShimcacheBlob_Win10(t *testing.T) {
	mod := ft(1600000000) // 2020-09-13T12:26:40Z
	blob := buildShimBlob(shimWin10Stats, "10ts", [][]byte{
		shimWin10Body(`C:\Windows\System32\example.exe`, mod),
		shimWin10Body(`D:\tools\sample.dll`, ft(1600000100)),
	})
	entries, notes := parseShimcacheBlob(blob)
	if len(entries) != 2 || len(notes) != 0 {
		t.Fatalf("条目/notes 数不符: %d/%v", len(entries), notes)
	}
	e0 := entries[0]
	if e0.Position != 0 || e0.Path != `C:\Windows\System32\example.exe` ||
		e0.WinVer != "win10" || e0.HasExec || !e0.LastModOK ||
		e0.CRC32 != 0xC0DE0000 || e0.EntryLen != uint32(len(shimWin10Body(
		`C:\Windows\System32\example.exe`, mod))) {
		t.Fatalf("首条目字段不符: %+v", e0)
	}
	// 事件形状 + TsUTCDirect 直通 + 文案纪律
	rec := shimcacheRecord(1, "ControlSet001", e0)
	if rec.Norm["event_type"] != "shimcache_entry_full" ||
		rec.Norm["last_modified_utc"] != "2020-09-13T12:26:40Z" ||
		rec.Norm["controlset"] != "ControlSet001" {
		t.Fatalf("事件字段不符: %+v", rec.Norm)
	}
	if _, has := rec.Norm["exec_flag"]; has {
		t.Fatal("Win10 条目不应有 exec_flag")
	}
	note, _ := rec.Norm["note"].(string)
	if !strings.Contains(note, "时间戳是文件最后修改时间,不是执行时间") ||
		!strings.Contains(note, "Shimcache 出现不证明执行") {
		t.Fatalf("文案纪律缺失: %q", note)
	}
	if rec.TsUTCDirect == nil ||
		!rec.TsUTCDirect.Equal(time.Unix(1600000000, 0).UTC()) {
		t.Fatalf("TsUTCDirect 不符: %v", rec.TsUTCDirect)
	}
	if rec.Raw != "ControlSet001/AppCompatCache/#0" {
		t.Fatalf("Raw 锚点不符: %q", rec.Raw)
	}
}

func TestShimcacheBlob_Win10CreatorsAndWin8(t *testing.T) {
	// Creators:魔数在 0x34(0x30 处为零不匹配 win10,判定顺序照树庭)
	blob := buildShimBlob(shimWin10CreatorsStat, "10ts", [][]byte{
		shimWin10Body(`C:\a.exe`, ft(1600000000))})
	entries, _ := parseShimcacheBlob(blob)
	if len(entries) != 1 || entries[0].WinVer != "win10_creators" {
		t.Fatalf("win10_creators 判定不符: %+v", entries)
	}
	// Win8:0x80 处 "00ts",exec_flag=flags&0x2
	blob8 := buildShimBlob(shimWin8Stats, "00ts", [][]byte{
		shimWin8Body(`C:\b.exe`, 0x2, ft(1600000000)),
		shimWin8Body(`C:\c.exe`, 0x0, ft(1600000000)),
	})
	e8, n8 := parseShimcacheBlob(blob8)
	if len(e8) != 2 || len(n8) != 0 {
		t.Fatalf("win8 条目数不符: %d/%v", len(e8), n8)
	}
	if !e8[0].HasExec || !e8[0].ExecFlag || e8[1].ExecFlag ||
		e8[0].WinVer != "win8" {
		t.Fatalf("win8 exec_flag 不符: %+v", e8)
	}
	// Win8.1:0x80 处 "10ts"
	blob81 := buildShimBlob(shimWin8Stats, "10ts", [][]byte{
		shimWin8Body(`C:\d.exe`, 0x2, ft(1600000000))})
	e81, _ := parseShimcacheBlob(blob81)
	if len(e81) != 1 || e81[0].WinVer != "win8.1" || !e81[0].ExecFlag {
		t.Fatalf("win8.1 判定不符: %+v", e81)
	}
}

func TestShimcacheBlob_Negative(t *testing.T) {
	// 未知魔数 → 0 条目 + note(不文件级 failed,树庭同款)
	entries, notes := parseShimcacheBlob([]byte("badc0ffe garbage payload"))
	if len(entries) != 0 || len(notes) == 0 ||
		!strings.Contains(notes[0], "魔数不识别") {
		t.Fatalf("未知魔数应 0 条目+note: %d/%v", len(entries), notes)
	}
	// 条目魔数错位 → 已解条目保留,后续不再猜
	good := shimWin10Body(`C:\ok.exe`, ft(1600000000))
	blob := buildShimBlob(shimWin10Stats, "10ts", [][]byte{good})
	blob = append(blob, []byte("XXXX")...)
	var h [8]byte
	binary.LittleEndian.PutUint32(h[4:], 4)
	blob = append(blob, h[:]...)
	blob = append(blob, 1, 2, 3, 4)
	entries, notes = parseShimcacheBlob(blob)
	if len(entries) != 1 || len(notes) == 0 ||
		!strings.Contains(notes[0], "结构到此为止") {
		t.Fatalf("魔数错位应保留已解+note: %d/%v", len(entries), notes)
	}
	// entry_len 越界 → 截断如实计数
	blob = make([]byte, shimWin10Stats)
	blob = append(blob, []byte("10ts")...)
	binary.LittleEndian.PutUint32(h[4:], 0xFFFFFF)
	blob = append(blob, h[:]...)
	entries, notes = parseShimcacheBlob(blob)
	if len(entries) != 0 || len(notes) == 0 ||
		!strings.Contains(notes[len(notes)-1], "截断/越界") {
		t.Fatalf("entry_len 越界应截断计数: %d/%v", len(entries), notes)
	}
	// path_len 越界 → 该条跳过不猜
	badBody := make([]byte, 4)
	binary.LittleEndian.PutUint16(badBody, 0xFF00)
	blob = buildShimBlob(shimWin10Stats, "10ts", [][]byte{badBody})
	entries, notes = parseShimcacheBlob(blob)
	if len(entries) != 0 || len(notes) == 0 ||
		!strings.Contains(notes[0], "path_len") {
		t.Fatalf("path_len 越界应跳过+note: %d/%v", len(entries), notes)
	}
	// 非法 FILETIME(0)→ 条目保留,时间不置不猜
	blob = buildShimBlob(shimWin10Stats, "10ts",
		[][]byte{shimWin10Body(`C:\zero.exe`, 0)})
	entries, _ = parseShimcacheBlob(blob)
	if len(entries) != 1 || entries[0].LastModOK {
		t.Fatalf("FILETIME=0 应 LastModOK=false: %+v", entries[0])
	}
	rec := shimcacheRecord(1, "ControlSet001", entries[0])
	if _, has := rec.Norm["last_modified_utc"]; has || rec.TsUTCDirect != nil {
		t.Fatal("非法 FILETIME 不应置时间字段")
	}
}

// buildSamF 造 SAM F 值(80B)。
func buildSamF(lastLogon, pwdSet, acctExp, lastFail uint64, rid, acb uint16,
	badPwd, logins uint16) []byte {
	f := make([]byte, 80)
	binary.LittleEndian.PutUint64(f[8:], lastLogon)
	binary.LittleEndian.PutUint64(f[24:], pwdSet)
	binary.LittleEndian.PutUint64(f[32:], acctExp)
	binary.LittleEndian.PutUint64(f[40:], lastFail)
	binary.LittleEndian.PutUint16(f[48:], rid)
	binary.LittleEndian.PutUint16(f[56:], acb)
	binary.LittleEndian.PutUint16(f[64:], badPwd)
	binary.LittleEndian.PutUint16(f[66:], logins)
	return f
}

// buildSamV 造 SAM V 值(字符串表自 0xCC 起;rel 相对 0xCC)。
func buildSamV(username, fullname, comment string) []byte {
	v := make([]byte, 0xCC)
	put := func(off int, s string) {
		b := u16str(s)
		if len(b) == 0 {
			return // 长度 0 槽位留零(空串 → 字段不置,树庭 None 同款)
		}
		binary.LittleEndian.PutUint32(v[off:], uint32(len(v)-0xCC))
		binary.LittleEndian.PutUint32(v[off+4:], uint32(len(b)))
		v = append(v, b...)
	}
	put(0x0C, username)
	put(0x18, fullname)
	put(0x24, comment)
	return v
}

func TestSamFV_Fields(t *testing.T) {
	pwdSet := ft(1600000000)
	f := buildSamF(ft(1600001000), pwdSet, 0, ft(1600002000),
		0x1F4, 0x0210, 3, 42)
	v := buildSamV("testuser", "Test User", "合成注释")
	fv, notes := parseSamFV(f, v)
	if len(notes) != 0 {
		t.Fatalf("不应有 notes: %v", notes)
	}
	rec := samAccountRecord(1, "000001F4", "S-1-5-21-1001-1002-1003", fv)
	n := rec.Norm
	if n["event_type"] != "sam_account" || n["rid"] != 500 ||
		n["sid"] != "S-1-5-21-1001-1002-1003-500" ||
		n["machine_sid"] != "S-1-5-21-1001-1002-1003" ||
		n["username"] != "testuser" || n["fullname"] != "Test User" ||
		n["comment"] != "合成注释" {
		t.Fatalf("账户字段不符: %+v", n)
	}
	if n["acb_flags"] != uint16(0x0210) || n["disabled"] != false ||
		n["bad_password_count"] != uint16(3) || n["login_count"] != uint16(42) {
		t.Fatalf("ACB/计数字段不符: %+v", n)
	}
	decoded, _ := n["acb_decoded"].([]string)
	if len(decoded) != 2 || decoded[0] != "normal_account" ||
		decoded[1] != "pwd_not_expires" {
		t.Fatalf("acb_decoded 不符: %v", decoded)
	}
	if n["password_last_set_utc"] != "2020-09-13T12:26:40Z" ||
		n["last_logon_utc"] == nil || n["last_failed_logon_utc"] == nil {
		t.Fatalf("时间字段不符: %+v", n)
	}
	if _, has := n["account_expires_utc"]; has {
		t.Fatal("acct_expires=0(非法 FILETIME)不应置字段")
	}
	if rec.TsUTCDirect == nil ||
		!rec.TsUTCDirect.Equal(time.Unix(1600000000, 0).UTC()) {
		t.Fatalf("ts 应取 password_last_set 直通: %v", rec.TsUTCDirect)
	}
	// 无机器 SID:sid/machine_sid 缺省(不猜)
	rec2 := samAccountRecord(2, "000001F5", "", fv)
	if _, has := rec2.Norm["sid"]; has {
		t.Fatal("无机器 SID 不应拼 sid")
	}
	// 禁用账户位
	fvDis, _ := parseSamFV(buildSamF(0, 0, 0, 0, 0x1F5, 0x0211, 0, 0),
		buildSamV("g", "", ""))
	rec3 := samAccountRecord(3, "000001F5", "", fvDis)
	if rec3.Norm["disabled"] != true {
		t.Fatalf("disabled 位解码不符: %+v", rec3.Norm)
	}
}

func TestSamFV_Negative(t *testing.T) {
	// F 不足 68 → 结构未解 + note;RID 退回键名十六进制
	fv, notes := parseSamFV(make([]byte, 40), buildSamV("u", "", ""))
	if fv.HasF || len(notes) == 0 || !strings.Contains(notes[0], "不足 68") {
		t.Fatalf("F 短应 note: %+v/%v", fv, notes)
	}
	rec := samAccountRecord(1, "000001F4", "", fv)
	if rec.Norm["rid"] != 500 {
		t.Fatalf("RID 应退回键名十六进制: %+v", rec.Norm)
	}
	if _, has := rec.Norm["acb_flags"]; has {
		t.Fatal("F 短不应有 acb_flags")
	}
	// V 不足 0xCC → 用户名未解 + note
	_, notes = parseSamFV(buildSamF(0, 0, 0, 0, 1, 0x10, 0, 0),
		make([]byte, 100))
	if len(notes) == 0 || !strings.Contains(notes[len(notes)-1], "不足 0xCC") {
		t.Fatalf("V 短应 note: %v", notes)
	}
	// V 字符串偏移越界 → 该字段不置 + note,其它字段不受影响
	v := buildSamV("okname", "", "")
	binary.LittleEndian.PutUint32(v[0x18:], 0xFFFFF) // fullname rel 越界
	binary.LittleEndian.PutUint32(v[0x1C:], 100)
	fv2, notes2 := parseSamFV(buildSamF(0, 0, 0, 0, 1, 0x10, 0, 0), v)
	if !fv2.HasUsername || fv2.HasFullname {
		t.Fatalf("越界应只丢 fullname: %+v", fv2)
	}
	found := false
	for _, nt := range notes2 {
		if strings.Contains(nt, "fullname") && strings.Contains(nt, "越界") {
			found = true
		}
	}
	if !found {
		t.Fatalf("越界 note 缺失: %v", notes2)
	}
}

// buildBinarySID 造二进制 SID(rev=1, authority, subs...)。
func buildBinarySID(authority uint64, subs ...uint32) []byte {
	b := []byte{1, byte(len(subs))}
	for i := 5; i >= 0; i-- {
		b = append(b, byte(authority>>(8*i)))
	}
	for _, s := range subs {
		var c [4]byte
		binary.LittleEndian.PutUint32(c[:], s)
		b = append(b, c[:]...)
	}
	return b
}

func TestDecodeBinarySID(t *testing.T) {
	sid := decodeBinarySID(buildBinarySID(5, 21, 1001, 1002, 1003))
	if sid != "S-1-5-21-1001-1002-1003" {
		t.Fatalf("SID 解码不符: %q", sid)
	}
	if got := decodeBinarySID(buildBinarySID(16, 32)); got != "S-1-16-32" {
		t.Fatalf("单子机构 SID 不符: %q", got)
	}
	// 负样本:rev!=1 / count=0 / 截断
	bad := buildBinarySID(5, 21)
	bad[0] = 2
	if decodeBinarySID(bad) != "" {
		t.Fatal("rev!=1 应拒")
	}
	if decodeBinarySID([]byte{1, 0, 0, 0, 0, 0, 0, 5}) != "" {
		t.Fatal("count=0 应拒")
	}
	if decodeBinarySID(buildBinarySID(5, 21, 1001)[:10]) != "" {
		t.Fatal("截断应拒")
	}
	if decodeBinarySID(nil) != "" {
		t.Fatal("空应拒")
	}
}

func TestMachineSIDFromAccountV(t *testing.T) {
	v := append([]byte("filler8B"), buildBinarySID(5, 21, 7, 8, 9)...)
	sid, note := machineSIDFromAccountV(v)
	if sid != "S-1-5-21-7-8-9" || note != "" {
		t.Fatalf("机器 SID 不符: %q/%q", sid, note)
	}
	if _, note := machineSIDFromAccountV(make([]byte, 10)); note == "" {
		t.Fatal("V 不足 24 应 note 不猜")
	}
	bad := make([]byte, 30) // 末 24 字节 rev=0 → 非法
	if _, note := machineSIDFromAccountV(bad); note == "" {
		t.Fatal("非法 SID 结构应 note 不猜")
	}
}

func TestUnicodeStringBlobAndGUID(t *testing.T) {
	// UNICODE_STRING blob:u16 len + u16 maxlen + u32 pad + UTF-16LE
	name := u16str("EXAMPLE")
	blob := make([]byte, 8)
	binary.LittleEndian.PutUint16(blob[0:], uint16(len(name)))
	binary.LittleEndian.PutUint16(blob[2:], uint16(len(name)+2))
	blob = append(blob, name...)
	s, ok, note := parseUnicodeStringBlob(blob)
	if !ok || s != "EXAMPLE" || note != "" {
		t.Fatalf("域名解码不符: %q/%v/%q", s, ok, note)
	}
	if _, ok, _ := parseUnicodeStringBlob(nil); ok {
		t.Fatal("空 blob 应 (无, 无 note)")
	}
	if _, _, note := parseUnicodeStringBlob([]byte{1, 2, 3}); note == "" {
		t.Fatal("短 blob 应 note")
	}
	over := make([]byte, 8)
	binary.LittleEndian.PutUint16(over[0:], 500)
	if _, _, note := parseUnicodeStringBlob(over); note == "" {
		t.Fatal("声明长度越界应 note 不猜")
	}
	// GUID:Data1/2/3 LE,全零=None
	g := []byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66,
		0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	gs, ok, _ := parseGuidBlob(g)
	if !ok || gs != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("GUID 不符: %q/%v", gs, ok)
	}
	if _, ok, _ := parseGuidBlob(make([]byte, 16)); ok {
		t.Fatal("全零 GUID 应为 None")
	}
	if _, _, note := parseGuidBlob([]byte{1, 2}); note == "" {
		t.Fatal("短 GUID 应 note")
	}
}

// buildPolAdtEv 造 PolAdtEv blob:12B 头(variant@8)+ N×u16。
func buildPolAdtEv(totalLen int, variant uint16, valueOf func(i int) uint16) []byte {
	b := make([]byte, totalLen)
	binary.LittleEndian.PutUint16(b[8:], variant)
	for i := 0; i*2+12+2 <= totalLen; i++ {
		binary.LittleEndian.PutUint16(b[12+2*i:], valueOf(i))
	}
	return b
}

func TestPolAdtEv_Versions(t *testing.T) {
	// 138B/0x78 = win7_2008,53 类
	blob := buildPolAdtEv(138, 0x78, func(i int) uint16 { return uint16(i % 4) })
	entries, notes, version, prov := parsePolAdtEv(blob)
	if version != "win7_2008" || prov || len(entries) != 53 || len(notes) != 0 {
		t.Fatalf("win7 版本不符: %q/%v/%d/%v", version, prov, len(entries), notes)
	}
	if entries[0].Category != "System" ||
		entries[0].Subcategory != "Security State Change" ||
		entries[0].Setting != "N" || entries[1].Setting != "S" ||
		entries[2].Setting != "F" || entries[3].Setting != "S/F" {
		t.Fatalf("设置解码不符: %+v", entries[:4])
	}
	// 值 >3 → setting 不置 + note
	blob = buildPolAdtEv(148, 0x82, func(i int) uint16 {
		if i == 0 {
			return 9
		}
		return 0
	})
	entries, notes, version, _ = parsePolAdtEv(blob)
	if version != "win10_early" || len(entries) != 58 {
		t.Fatalf("win10_early 不符: %q/%d", version, len(entries))
	}
	if entries[0].HasSetting || len(notes) == 0 {
		t.Fatalf("值 9 应留原值+note: %+v/%v", entries[0], notes)
	}
	// 150B/0x84 = win10_1607plus_2016_2022,59 类
	blob = buildPolAdtEv(150, 0x84, func(i int) uint16 { return 1 })
	entries, _, version, _ = parsePolAdtEv(blob)
	if version != "win10_1607plus_2016_2022" || len(entries) != 59 {
		t.Fatalf("win10_1607plus 不符: %q/%d", version, len(entries))
	}
}

func TestPolAdtEv_UnknownVariant(t *testing.T) {
	// Win11 152B/0x86 未知变体:u16 数 70 ≥ 59 → 按共有前 59 类解,provisional
	blob := buildPolAdtEv(152, 0x86, func(i int) uint16 { return 3 })
	entries, notes, version, prov := parsePolAdtEv(blob)
	if !prov || len(entries) != 59 || version != "unknown(len=152,id=0x86)" {
		t.Fatalf("未知变体应 provisional: %q/%v/%d", version, prov, len(entries))
	}
	if !entries[0].Provisional || len(notes) == 0 ||
		!strings.Contains(notes[0], "provisional") {
		t.Fatalf("provisional 标注缺失: %+v/%v", entries[0], notes)
	}
	// 可用 u16 不足 59 → 全不猜
	blob = buildPolAdtEv(60, 0x86, func(i int) uint16 { return 0 })
	entries, notes, version, prov = parsePolAdtEv(blob)
	if len(entries) != 0 || prov || len(notes) == 0 ||
		!strings.Contains(notes[0], "全部不猜") {
		t.Fatalf("不足 59 应全不猜: %d/%v/%q", len(entries), prov, version)
	}
	// 不足 12 字节头
	_, notes, _, _ = parsePolAdtEv([]byte{1, 2, 3})
	if len(notes) == 0 {
		t.Fatal("短 blob 应 note")
	}
}

// buildPrivilgs 造 Privilgs blob:u32 计数 + u32 pad + N×(LUID u64+attr u32)。
func buildPrivilgs(declared uint32, luidAttr ...[2]uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint32(b[0:], declared)
	for _, la := range luidAttr {
		var c [12]byte
		binary.LittleEndian.PutUint64(c[0:], la[0])
		binary.LittleEndian.PutUint32(c[8:], uint32(la[1]))
		b = append(b, c[:]...)
	}
	return b
}

func TestPrivilgs(t *testing.T) {
	blob := buildPrivilgs(2, [2]uint64{2, 1}, [2]uint64{99, 0})
	entries, notes := parsePrivilgs(blob)
	if len(entries) != 2 {
		t.Fatalf("条目数不符: %d", len(entries))
	}
	if entries[0].Name != "SeCreateTokenPrivilege" || !entries[0].EnabledDefault ||
		entries[0].Attr != 1 || entries[0].Position != 0 {
		t.Fatalf("首条不符: %+v", entries[0])
	}
	if entries[1].HasName || entries[1].EnabledDefault {
		t.Fatalf("未知 LUID 应留数字不猜: %+v", entries[1])
	}
	found := false
	for _, n := range notes {
		if strings.Contains(n, "LUID 99") {
			found = true
		}
	}
	if !found {
		t.Fatalf("未知 LUID note 缺失: %v", notes)
	}
	// 声明计数越界 → 截断如实记
	blob = buildPrivilgs(9, [2]uint64{17, 3}, [2]uint64{18, 0})
	entries, notes = parsePrivilgs(blob)
	if len(entries) != 2 || len(notes) == 0 ||
		!strings.Contains(notes[0], "截断") {
		t.Fatalf("越界应截断+note: %d/%v", len(entries), notes)
	}
	if entries[0].Name != "SeBackupPrivilege" || !entries[0].EnabledDefault {
		t.Fatalf("LUID 17 解码不符: %+v", entries[0])
	}
	// 不足 8 字节头
	if _, notes := parsePrivilgs([]byte{1, 2}); len(notes) == 0 {
		t.Fatal("短 blob 应 note")
	}
}

// ==================== hive 级(testdata NTUSER.DAT 真实 regf,无本专题键) ====================

func TestRegistryTopics_NonHive(t *testing.T) {
	p := writeTemp(t, "SYSTEM", []byte("definitely not a hive"))
	for name, parser := range map[string]Parser{
		"shimcache": ShimcacheHiveParser{}, "sam": SamAccountsParser{},
		"security": SecurityPolicyParser{}} {
		if _, err := parser.Records(p); err == nil {
			t.Fatalf("%s: 非 regf 应文件级如实 failed", name)
		}
	}
}

// NTUSER.DAT 是真实 regf 但无 ControlSet/SAM/Policy 键:三 parser 应成功
// 打开,0 事件 + summary,notes 如实记缺失(不文件级 failed,零静默)。
func TestRegistryTopics_NoTopicKeys(t *testing.T) {
	const ntuser = "../../testdata/parsers/NTUSER.DAT"
	if _, err := os.Stat(ntuser); err != nil {
		t.Skipf("testdata 缺失: %v", err)
	}
	for name, parser := range map[string]Parser{
		"shimcache": ShimcacheHiveParser{}, "sam": SamAccountsParser{},
		"security": SecurityPolicyParser{}} {
		stream, err := parser.Records(ntuser)
		if err != nil {
			t.Fatalf("%s: 合法 hive 不应文件级失败: %v", name, err)
		}
		recs := drain(t, stream)
		if len(recs) != 1 || recs[0].Norm["event_type"] != "registry_topics_summary" {
			t.Fatalf("%s: 应只有 summary: %+v", name, recs)
		}
		sum := recs[0].Norm["summary"].(map[string]any)
		counts := sum["counts"].(map[string]int)
		for k, c := range counts {
			if c != 0 {
				t.Fatalf("%s: %s 应为 0: %d", name, k, c)
			}
		}
		notes, _ := sum["notes"].([]string)
		if len(notes) == 0 {
			t.Fatalf("%s: 缺键应如实记 notes", name)
		}
		t.Logf("%s notes: %v", name, notes)
	}
}

// ==================== 凭据材料纪律焊死(原则性不碰) ====================

// 源码级断言:本文件的键打开调用永不指向 Secrets/PolEKList/PolOldSyskey/
// SecDesc;Cache 值永不调 ValueData(内容一个字节不解)。
func TestRegistryTopics_CredentialDiscipline(t *testing.T) {
	src, err := os.ReadFile("registry_topics.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(src), "\n") {
		for _, forbidden := range []string{"Secrets", "PolEKList",
			"PolOldSyskey", "SecDesc"} {
			if strings.Contains(line, forbidden) &&
				(strings.Contains(line, "openKeyPath(") ||
					strings.Contains(line, "OpenKey(") ||
					strings.Contains(line, "findHiveValue(")) {
				t.Fatalf("原则性不碰键被打开: %s", strings.TrimSpace(line))
			}
		}
		if strings.Contains(line, "cache.Values()") &&
			strings.Contains(line, "ValueData") {
			t.Fatalf("Cache 值内容被读取: %s", strings.TrimSpace(line))
		}
	}
}

// ==================== 内存纪律(blob 级;regf 容器无法合成,见文件头) ====================

// 256MB 尾部垃圾 blob:魔数有效、首条后即 entry_len 越界 → 内存与输入大小
// 无关;另测 20000 条真实条目 → 条目结构有界。
func TestShimcacheBlob_MemoryFlat(t *testing.T) {
	if testing.Short() {
		t.Skip("short 模式跳过大输入内存用例")
	}
	// 大输入:256MB,有效魔数 + 1 条正常条目 + 1 条 entry_len 越界即终止
	big := make([]byte, shimWin10Stats)
	entry := shimWin10Body(`C:\Windows\System32\sample.exe`, ft(1600000000))
	hdr := func(entryLen uint32) []byte {
		b := []byte("10ts")
		var h [8]byte
		binary.LittleEndian.PutUint32(h[4:], entryLen)
		return append(b, h[:]...)
	}
	big = append(big, hdr(uint32(len(entry)))...)
	big = append(big, entry...)
	big = append(big, hdr(0x7FFFFFFF)...)       // 越界 → 终止
	big = append(big, make([]byte, 256<<20)...) // 尾部垃圾不参与解析
	var m0, m1 runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&m0)
	entries, notes := parseShimcacheBlob(big)
	runtime.GC()
	runtime.ReadMemStats(&m1)
	if len(entries) != 1 || len(notes) == 0 {
		t.Fatalf("大输入条目/notes 不符: %d/%v", len(entries), notes)
	}
	delta := int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	if delta > 64<<20 {
		t.Fatalf("256MB 输入堆增量 %d MB 超 64MB 纪律线", delta>>20)
	}
	t.Logf("256MB 尾部垃圾:entries=%d,堆增量 %.1f MB", len(entries),
		float64(delta)/(1<<20))

	// 多条目:20000 条 → 解析产物有界
	bodies := make([][]byte, 20000)
	for i := range bodies {
		bodies[i] = entry
	}
	many := buildShimBlob(shimWin10Stats, "10ts", bodies)
	runtime.GC()
	runtime.ReadMemStats(&m0)
	entries, _ = parseShimcacheBlob(many)
	runtime.GC()
	runtime.ReadMemStats(&m1)
	if len(entries) != 20000 {
		t.Fatalf("条目数不符: %d", len(entries))
	}
	delta = int64(m1.HeapAlloc) - int64(m0.HeapAlloc)
	if delta > 64<<20 {
		t.Fatalf("20000 条堆增量 %d MB 超 64MB 纪律线", delta>>20)
	}
	t.Logf("20000 条(%d MB blob):堆增量 %.1f MB", len(many)>>20,
		float64(delta)/(1<<20))
}

// model 引用防 unused(事件类别常量在本文件断言中使用)。
var _ = model.KindEvent
