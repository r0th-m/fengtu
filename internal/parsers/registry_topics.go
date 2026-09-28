// registry 专题语义解析(M3 专题切片):Shimcache 二进制(SYSTEM hive)、
// SAM 账户(SAM hive)、SECURITY 明文政策三件半(SECURITY hive)。
//
// 语义基准 = 树庭 backend/app/parsers/registry_hive.py 的
// parse_shimcache_blob / parse_sam_fv / machine_sid_from_account_v /
// decode_binary_sid / _parse_security(金标准,逐字段对拍);格式契约全部对
// 公开 spec 写(Mandiant ShimCacheParser / RegRipper samparse·polacdmn·
// auditpol·lsa / MS-LSAD Privilege Data Model),不对具体案件值写。
//
// hive 容器复用 Velocidex regparser(见 registry.go 选型注释);键查找不用
// OpenKey(它按 Name() 原字节比较,非 ASCII 键名有 registry.go 注释的编码
// 怪癖),一律从根键用 hiveKeyName 解码后 EqualFold 逐层下钻。
//
// 与树庭的口径差(如实):
//   - 树庭三专题收在一个 registry_hive parser 里按文件名分派;丰图拆成三个
//     独立 Parser(映射表按文件名指到对应 parser),事件字段逐一对齐;
//   - 树庭 UTC → utc_to_local_ts_raw 回转本地;丰图 TsUTCDirect 直通 +
//     Norm 里 *_utc ISO 留证(同 efu/registry 切片纪律);
//   - 树庭键不存在靠 except 捕获;regparser 下钻返回 nil,等价语义;
//   - 收尾事件统一 registry_topics_summary(topic 区分三类),对应树庭
//     registry_hive_summary 的 counts+warnings(此处 notes≡warnings)。
//
// 凭据材料纪律(原则性不碰,测试焊死):不 open Policy\Secrets、PolEKList、
// PolOldSyskey、SecDesc;Cache\NL$1..NL$10 只数值存在数与声明尺寸
// (vk.DataLength,不读内容一个字节)。
//
// 流式纪律:hive 值量级小(SAM 账户/政策条目百级,Shimcache 生产上限 1024/
// CS),记录先入缓冲再逐条放出,同 registry.go 的 hiveStream 模式;
// Shimcache 条目上限 shimMaxEntries 防结构错位,blob 级解析零预分配。
package parsers

import (
	"encoding/binary"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"www.velocidex.com/golang/regparser"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// ---- Shimcache 二进制(Mandiant ShimCacheParser spec,逐字段对齐树庭) ----
const (
	shimWin8Stats         = 0x80
	shimWin10Stats        = 0x30
	shimWin10CreatorsStat = 0x34
	shimCSRSSFlag         = 0x2
	shimMaxEntries        = 100000 // 合理性上限(防结构错位死循环,树庭同款)
)

// ---- SAM ACB 位义(RegRipper samparse spec,照抄树庭 _ACB_BITS) ----
var samACBBits = []struct {
	bit   uint16
	label string
}{
	{0x0001, "disabled"}, {0x0002, "home_dir_required"},
	{0x0004, "password_not_required"}, {0x0008, "temp_duplicate"},
	{0x0010, "normal_account"}, {0x0020, "mns_logon"},
	{0x0040, "interdomain_trust"}, {0x0080, "workstation_trust"},
	{0x0100, "server_trust"}, {0x0200, "pwd_not_expires"},
	{0x0400, "auto_locked"},
}

var (
	controlSetRe = regexp.MustCompile(`(?i)^controlset\d{3,}$`)
	ridKeyRe     = regexp.MustCompile(`^[0-9a-fA-F]{8}$`) // Users\000001F4 形式
	accountSIDRe = regexp.MustCompile(`^S-\d+-\d+`)
	cacheSlotRe  = regexp.MustCompile(`(?i)^NL\$\d+$`)
)

// ==================== 共享 hive 助手(专题用) ====================

// openKeyPath 从 root 逐层下钻(键名 hiveKeyName 解码后大小写不敏感比较,
// 绕开 regparser OpenKey 按 Name() 原字节比较的非 ASCII 怪癖);
// 任一层不存在 → nil(调用方如实记 note,不猜)。
func openKeyPath(root *regparser.CM_KEY_NODE, path string) *regparser.CM_KEY_NODE {
	cur := root
	for _, comp := range strings.Split(path, "\\") {
		if comp == "" {
			continue
		}
		var next *regparser.CM_KEY_NODE
		for _, sk := range cur.Subkeys() {
			if strings.EqualFold(hiveKeyName(sk), comp) {
				next = sk
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

// hiveValueBytes 值 → 原始字节。类型化为字符串/整数的值
// (SZ/EXPAND_SZ/MULTI_SZ/DWORD/QWORD/LINK)按树庭 isinstance(val, bytes)
// 口径不算字节串 → ok=false;inline 值多读按 DataSize 截(regparser 怪癖,
// 见 registry.go renderHiveValue 注释)。
func hiveValueBytes(v *regparser.CM_KEY_VALUE) ([]byte, bool) {
	switch v.Type() {
	case regparser.REG_SZ, regparser.REG_EXPAND_SZ, regparser.REG_MULTI_SZ,
		regparser.REG_DWORD, regparser.REG_DWORD_BIG_ENDIAN,
		regparser.REG_QWORD, regparser.REG_LINK:
		return nil, false
	}
	vd := v.ValueData()
	if vd == nil {
		return nil, false
	}
	b := vd.Data
	if sz := v.DataSize(); sz >= 0 && int64(len(b)) > sz {
		b = b[:sz]
	}
	return b, true
}

// findHiveValue 按键名取值(大小写不敏感);无 → nil。
func findHiveValue(k *regparser.CM_KEY_NODE, name string) *regparser.CM_KEY_VALUE {
	for _, v := range k.Values() {
		if strings.EqualFold(hiveValueName(v), name) {
			return v
		}
	}
	return nil
}

// defaultHiveBytes 键的首个字节串值(树庭 _default_bytes 同款:遍历值表,
// 第一个按字节口径成立的即返回;这些政策键常态只有 (Default) 一个值)。
func defaultHiveBytes(k *regparser.CM_KEY_NODE) ([]byte, bool) {
	for _, v := range k.Values() {
		if b, ok := hiveValueBytes(v); ok {
			return b, true
		}
	}
	return nil, false
}

// keyLastWrite 键 last-write(FILETIME 原生 UTC)→ (time, ISO);
// 零值/无 → (nil, "")(不猜)。
func keyLastWrite(k *regparser.CM_KEY_NODE) (*time.Time, string) {
	if lw := k.LastWriteTime(); lw != nil && !lw.Time.IsZero() {
		t := lw.Time.UTC()
		return &t, t.Format("2006-01-02T15:04:05Z")
	}
	return nil, ""
}

// topicStream 记录缓冲流(同 registry.go hiveStream 模式:
// 提取在 Records 内完成,Next 逐条放出)。
type topicStream struct {
	f    *os.File
	recs []model.Record
	pos  int
}

func (s *topicStream) Next() (model.Record, bool) {
	if s.pos >= len(s.recs) {
		return model.Record{}, false
	}
	rec := s.recs[s.pos]
	s.pos++
	return rec, true
}

func (s *topicStream) Err() error   { return nil }
func (s *topicStream) Close() error { return s.f.Close() }

// openTopicHive 打开 regf hive(非 regf/损坏 → 文件级如实 failed)。
func openTopicHive(path string) (*os.File, *regparser.Registry,
	*regparser.CM_KEY_NODE, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("hive 打开失败: %w", err)
	}
	hive, err := regparser.NewRegistry(f)
	if err != nil {
		f.Close()
		return nil, nil, nil, fmt.Errorf("非 regf 结构或损坏(%s): %w", path, err)
	}
	root := hive.OpenKey("")
	if root == nil {
		f.Close()
		return nil, nil, nil, fmt.Errorf("根键读取失败(hive 结构异常): %s", path)
	}
	return f, hive, root, nil
}

// topicSummaryRecord 收尾 registry_topics_summary 事件
// (对应树庭 registry_hive_summary:counts + warnings;此处 notes≡warnings)。
func topicSummaryRecord(topic string, counts map[string]int,
	notes []string, extra map[string]any) model.Record {

	summary := map[string]any{
		"topic":       topic,
		"counts":      counts,
		"notes":       notes,
		"notes_count": len(notes),
	}
	for k, v := range extra {
		summary[k] = v
	}
	return model.Record{LineNo: 1, Kind: model.KindEvent, // LineNo 由调用方落
		Norm: map[string]any{"event_type": "registry_topics_summary",
			"summary": summary},
		Raw: "<registry_topics_summary>"}
}

// ==================== 纯字节解码函数(regf 无关,合成样本直测) ====================

// shimEntry 一条 Shimcache 条目(Mandiant spec;树庭 parse_shimcache_blob
// 条目 dict 逐字段对应)。
type shimEntry struct {
	Position  int
	Path      string
	LastModFT uint64
	LastModOK bool // FILETIME 非法(0/溢出)→ false,字段不置不猜
	ExecFlag  bool
	HasExec   bool // Win8/8.1 才有 exec_flag;Win10 无此字段
	CRC32     uint32
	EntryLen  uint32
	WinVer    string
}

// parseShimcacheBlob AppCompatCache blob → (条目, notes)。
// 魔数定位:Win10 blob[0x30:0x34]=="10ts"(Creators 起 0x34)、
// Win8 [0x80:0x84]=="00ts"、Win8.1 [0x80:0x84]=="10ts"(判定顺序照树庭);
// 统计头后逐条目 12 字节头(magic 4s+crc32 u32+entry_len u32);
// 结构错位/截断:已解条目保留,notes 如实记,零静默;魔数全不认识 →
// 空列表+note(不文件级 failed,树庭同款)。
func parseShimcacheBlob(blob []byte) ([]shimEntry, []string) {
	var entries []shimEntry
	var notes []string
	stats := -1
	var magic, winVer string
	// 魔数位置判定(Mandiant read_cache spec,顺序与树庭逐一对齐)
	for _, cand := range []struct {
		off int
		mag string
		ver string
	}{{shimWin10Stats, "10ts", "win10"},
		{shimWin10CreatorsStat, "10ts", "win10_creators"},
		{shimWin8Stats, "00ts", "win8"},
		{shimWin8Stats, "10ts", "win8.1"}} {
		if len(blob) > cand.off && string(blob[cand.off:cand.off+4]) == cand.mag {
			stats, magic, winVer = cand.off, cand.mag, cand.ver
			break
		}
	}
	if stats < 0 {
		head := blob
		if len(head) > 4 {
			head = head[:4]
		}
		notes = append(notes, fmt.Sprintf("AppCompatCache 魔数不识别(前 %d 字节 %x;"+
			"XP/Win7 badc0ffe/badc0fee 系列本版不支持),未解析", len(head), head))
		return entries, notes
	}

	pos := stats
	truncated := 0
	for pos+12 <= len(blob) && len(entries) < shimMaxEntries {
		emagic := string(blob[pos : pos+4])
		crc32 := binary.LittleEndian.Uint32(blob[pos+4:])
		entryLen := binary.LittleEndian.Uint32(blob[pos+8:])
		if emagic != magic {
			notes = append(notes, fmt.Sprintf("条目 %d 处魔数 %q != %q,"+
				"结构到此为止,后续字节不再猜", len(entries), emagic, magic))
			break
		}
		pos += 12
		if entryLen == 0 || pos+int(entryLen) > len(blob) {
			truncated++
			break
		}
		edata := blob[pos : pos+int(entryLen)]
		pos += int(entryLen)
		pathLen := int(binary.LittleEndian.Uint16(edata))
		if 2+pathLen > len(edata) {
			notes = append(notes, fmt.Sprintf("条目 %d path_len %d 越界"+
				"(entry_len %d),该条跳过不猜", len(entries), pathLen, entryLen))
			truncated++
			continue
		}
		ent := shimEntry{
			Position: len(entries),
			Path:     utf16le(edata[2 : 2+pathLen]),
			CRC32:    crc32,
			EntryLen: entryLen,
			WinVer:   winVer,
		}
		var ft uint64
		if winVer == "win8" || winVer == "win8.1" {
			// Win8/8.1:path 后 package_len(u16)+package,再
			// 5×u32(flags/unk/low/high/unk)
			rest := 2 + pathLen
			if rest+2 > len(edata) {
				truncated++
				continue
			}
			pkgLen := int(binary.LittleEndian.Uint16(edata[rest:]))
			rest += 2 + pkgLen
			if rest+20 > len(edata) {
				truncated++
				continue
			}
			flags := binary.LittleEndian.Uint32(edata[rest:])
			low := binary.LittleEndian.Uint32(edata[rest+8:])
			high := binary.LittleEndian.Uint32(edata[rest+12:])
			ent.ExecFlag = flags&shimCSRSSFlag != 0
			ent.HasExec = true
			ft = uint64(high)<<32 | uint64(low)
		} else {
			// Win10:path 后直接 8 字节 FILETIME(last modified)
			rest := 2 + pathLen
			if rest+8 > len(edata) {
				truncated++
				continue
			}
			ft = binary.LittleEndian.Uint64(edata[rest:])
		}
		ent.LastModFT = ft
		_, ent.LastModOK = FiletimeToUTC(ft)
		entries = append(entries, ent)
	}
	if truncated > 0 {
		notes = append(notes, fmt.Sprintf("%d 条截断/越界未解,如实计数不猜", truncated))
	}
	if len(entries) >= shimMaxEntries {
		notes = append(notes, fmt.Sprintf("条目数达合理性上限 %d,停止(防结构错位)",
			shimMaxEntries))
	}
	return entries, notes
}

// decodeBinarySID 二进制 SID → S-1-5-... 文本;结构不合 → ""(不猜)。
// 布局:rev(1)+子机构数(1)+颁发机构(6,BE)+子机构×4(LE)。
func decodeBinarySID(raw []byte) string {
	if len(raw) < 8 {
		return ""
	}
	rev, count := raw[0], int(raw[1])
	if rev != 1 || count == 0 || len(raw) < 8+4*count {
		return ""
	}
	authority := uint64(0)
	for _, b := range raw[2:8] {
		authority = authority<<8 | uint64(b)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", rev, authority)
	for i := 0; i < count; i++ {
		fmt.Fprintf(&sb, "-%d",
			binary.LittleEndian.Uint32(raw[8+4*i:12+4*i]))
	}
	return sb.String()
}

// machineSIDFromAccountV SAM\Domains\Account 的 V 值末尾 24 字节 →
// 机器 SID(公开 DFIR spec);结构校验不过 → ("", 原因),不猜。
func machineSIDFromAccountV(v []byte) (string, string) {
	if len(v) < 24 {
		return "", fmt.Sprintf("V 值仅 %d 字节,不足 24,机器 SID 未取", len(v))
	}
	sid := decodeBinarySID(v[len(v)-24:])
	if sid == "" {
		return "", "V 值末尾 24 字节不是合法二进制 SID 结构,不猜"
	}
	return sid, ""
}

// samFV SAM 用户 F/V 值解码结果(RegRipper samparse spec;ok=false 的字段
// 不置,不猜)。
type samFV struct {
	LastLogonFT, PwdLastSetFT uint64
	AcctExpiresFT, LastFailFT uint64
	LastLogonOK, PwdSetOK     bool
	AcctExpiresOK, LastFailOK bool
	RID                       uint16
	HasF                      bool // F ≥68 字节
	ACB                       uint16
	BadPwdCount, LoginCount   uint16
	Username, Fullname        string
	Comment                   string
	HasUsername, HasFullname  bool
	HasComment                bool
}

// parseSamFV SAM 用户 F/V 值 → 账户字段;越界不猜,如实 notes。
// F(≥68B):0x08 last_logon、0x18 pwd_last_set、0x20 acct_expires、
// 0x28 last_failed(均 FILETIME UTC),0x30 RID u16、0x38 ACB u16、
// 0x40 bad_pwd_count u16、0x42 login_count u16;
// V(≥0xCC):字符串表自 0xCC 起,(相对偏移 u32, 长度 u32)对:
// username 0x0C/0x10、fullname 0x18/0x1C、comment 0x24/0x28(UTF-16LE)。
func parseSamFV(f, v []byte) (samFV, []string) {
	var out samFV
	var notes []string
	if len(f) >= 68 {
		out.HasF = true
		out.LastLogonFT = binary.LittleEndian.Uint64(f[8:16])
		out.PwdLastSetFT = binary.LittleEndian.Uint64(f[24:32])
		out.AcctExpiresFT = binary.LittleEndian.Uint64(f[32:40])
		out.LastFailFT = binary.LittleEndian.Uint64(f[40:48])
		_, out.LastLogonOK = FiletimeToUTC(out.LastLogonFT)
		_, out.PwdSetOK = FiletimeToUTC(out.PwdLastSetFT)
		_, out.AcctExpiresOK = FiletimeToUTC(out.AcctExpiresFT)
		_, out.LastFailOK = FiletimeToUTC(out.LastFailFT)
		out.RID = binary.LittleEndian.Uint16(f[48:50])
		out.ACB = binary.LittleEndian.Uint16(f[56:58])
		out.BadPwdCount = binary.LittleEndian.Uint16(f[64:66])
		out.LoginCount = binary.LittleEndian.Uint16(f[66:68])
	} else {
		notes = append(notes, fmt.Sprintf("F 值仅 %d 字节,不足 68,结构未解不猜",
			len(f)))
	}
	if len(v) >= 0xCC {
		for _, fld := range []struct {
			off  int
			name string
		}{{0x0C, "username"}, {0x18, "fullname"}, {0x24, "comment"}} {
			rel := int(binary.LittleEndian.Uint32(v[fld.off:]))
			size := int(binary.LittleEndian.Uint32(v[fld.off+4:]))
			start := 0xCC + rel
			if size <= 0 || start+size > len(v) {
				if size > 0 {
					notes = append(notes, fmt.Sprintf("V 值 %s 偏移越界"+
						"(rel=%d len=%d vlen=%d),不猜", fld.name, rel, size,
						len(v)))
				}
				continue
			}
			s := strings.TrimRight(utf16le(v[start:start+size]), "\x00")
			if s == "" {
				continue // 空串 → 字段不置(树庭 None 同款)
			}
			switch fld.name {
			case "username":
				out.Username, out.HasUsername = s, true
			case "fullname":
				out.Fullname, out.HasFullname = s, true
			case "comment":
				out.Comment, out.HasComment = s, true
			}
		}
	} else {
		notes = append(notes, fmt.Sprintf("V 值仅 %d 字节,不足 0xCC,用户名未解不猜",
			len(v)))
	}
	return out, notes
}

// parseUnicodeStringBlob PolAcDmN/PolPrDmN/PolDnDDN/PolDnTrN 默认值 → 名称
// (RegRipper polacdmn spec:u16 len + u16 maxlen + u32 pad + UTF-16LE
// len 字节)。空 blob(工作组机常见)→ ("", false, "");越界 → 原因,不猜。
func parseUnicodeStringBlob(raw []byte) (string, bool, string) {
	if len(raw) == 0 {
		return "", false, ""
	}
	if len(raw) < 8 {
		return "", false, fmt.Sprintf("仅 %d 字节,不足 8 字节 UNICODE_STRING 头",
			len(raw))
	}
	n := int(binary.LittleEndian.Uint16(raw))
	if n <= 0 {
		return "", false, ""
	}
	if 8+n > len(raw) {
		return "", false, fmt.Sprintf("声明长度 %d 越界(blob %d 字节),不猜",
			n, len(raw))
	}
	return strings.TrimRight(utf16le(raw[8:8+n]), "\x00"), true, ""
}

// parseGuidBlob PolDnDmG 默认值(16 字节二进制 GUID,Data1/2/3 LE)→ 文本;
// 全零=无域 GUID → ("", false, "")。
func parseGuidBlob(raw []byte) (string, bool, string) {
	if len(raw) == 0 {
		return "", false, ""
	}
	if len(raw) < 16 {
		return "", false, fmt.Sprintf("仅 %d 字节,不足 16 字节 GUID,不猜", len(raw))
	}
	allZero := true
	for _, b := range raw[:16] {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return "", false, ""
	}
	d1 := binary.LittleEndian.Uint32(raw)
	d2 := binary.LittleEndian.Uint16(raw[4:])
	d3 := binary.LittleEndian.Uint16(raw[6:])
	g := fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3, raw[8], raw[9], raw[10], raw[11], raw[12], raw[13],
		raw[14], raw[15])
	return g, true, ""
}

// ---- PolAdtEv 子类别顺序表(RegRipper auditpol.pl 逐版本照抄树庭) ----

var auditCatsWin7 = []string{ // 138B/0x78,Win7/2008,53 类
	"System:Security State Change", "System:Security System Extension",
	"System:System Integrity", "System:IPsec Driver", "System:Other System Events",
	"Logon/Logoff:Logon", "Logon/Logoff:Logoff", "Logon/Logoff:Account Lockout",
	"Logon/Logoff:IPsec Main Mode", "Logon/Logoff:IPsec Quick Mode",
	"Logon/Logoff:IPsec Extended Mode", "Logon/Logoff:Special Logon",
	"Logon/Logoff:Other Logon/Logoff Events", "Logon/Logoff:Network Policy Server",
	"Object Access:File System", "Object Access:Registry",
	"Object Access:Kernel Object", "Object Access:SAM",
	"Object Access:Other Object Access Events",
	"Object Access:Certification Services", "Object Access:Application Generated",
	"Object Access:Handle Manipulation", "Object Access:File Share",
	"Object Access:Filtering Platform Packet Drop",
	"Object Access:Filtering Platform Connection",
	"Object Access:Detailed File Share",
	"Privilege Use:Sensitive Privilege Use", "Privilege Use:Non Sensitive Privilege Use",
	"Privilege Use:Other Privilege Use Events",
	"Detailed Tracking:Process Creation", "Detailed Tracking:Process Termination",
	"Detailed Tracking:DPAPI Activity", "Detailed Tracking:RPC Events",
	"Policy Change:Audit Policy Change", "Policy Change:Authentication Policy Change",
	"Policy Change:Authorization Policy Change",
	"Policy Change:MPSSVC Rule-Level Policy Change",
	"Policy Change:Filtering Platform Policy Change",
	"Policy Change:Other Policy Change Events",
	"Account Management:User Account Management",
	"Account Management:Computer Account Management",
	"Account Management:Security Group Management",
	"Account Management:Distribution Group Management",
	"Account Management:Application Group Management",
	"Account Management:Other Account Management Events",
	"DS Access:Directory Service Access", "DS Access:Directory Service Changes",
	"DS Access:Directory Service Replication",
	"DS Access:Detailed Directory Service Replication",
	"Account Logon:Credential Validation",
	"Account Logon:Kerberos Service Ticket Operations",
	"Account Logon:Other Account Logon Events",
	"Account Logon:Kerberos Authentication Service",
}

var auditCatsWin10 = []string{ // 148B/0x82,Win10 早期,58 类
	"System:Security State Change", "System:Security System Extension",
	"System:System Integrity", "System:IPsec Driver", "System:Other System Events",
	"Logon/Logoff:Logon", "Logon/Logoff:Logoff", "Logon/Logoff:Account Lockout",
	"Logon/Logoff:IPsec Main Mode", "Logon/Logoff:IPsec Quick Mode",
	"Logon/Logoff:IPsec Extended Mode", "Logon/Logoff:Special Logon",
	"Logon/Logoff:Other Logon/Logoff Events", "Logon/Logoff:Network Policy Server",
	"Logon/Logoff:User Device Claims", "Logon/Logoff:Group Membership",
	"Object Access:File System", "Object Access:Registry",
	"Object Access:Kernel Object", "Object Access:SAM",
	"Object Access:Certification Services", "Object Access:Application Generated",
	"Object Access:Handle Manipulation", "Object Access:File Share",
	"Object Access:Filtering Platform Packet Drop",
	"Object Access:Filtering Platform Connection",
	"Object Access:Other Object Access Events", "Object Access:Detailed File Share",
	"Object Access:Removable Storage", "Object Access:Central Policy Staging",
	"Privilege Use:Sensitive Privilege Use", "Privilege Use:Non Sensitive Privilege Use",
	"Privilege Use:Other Privilege Use Events",
	"Detailed Tracking:Process Creation", "Detailed Tracking:Process Termination",
	"Detailed Tracking:DPAPI Activity", "Detailed Tracking:RPC Events",
	"Detailed Tracking:Plug and Play Events",
	"Policy Change:Audit Policy Change", "Policy Change:Authentication Policy Change",
	"Policy Change:Authorization Policy Change",
	"Policy Change:MPSSVC Rule-Level Policy Change",
	"Policy Change:Filtering Platform Policy Change",
	"Policy Change:Other Policy Change Events",
	"Account Management:User Account Management",
	"Account Management:Computer Account Management",
	"Account Management:Security Group Management",
	"Account Management:Distribution Group Management",
	"Account Management:Application Group Management",
	"Account Management:Other Account Management Events",
	"DS Access:Directory Service Access", "DS Access:Directory Service Changes",
	"DS Access:Directory Service Replication",
	"DS Access:Detailed Directory Service Replication",
	"Account Logon:Credential Validation",
	"Account Logon:Kerberos Service Ticket Operations",
	"Account Logon:Other Account Logon Events",
	"Account Logon:Kerberos Authentication Service",
}

var auditCatsWin2016 = []string{ // 150B/0x84,Win10 1607+/2016-2022,59 类
	"System:Security State Change", "System:Security System Extension",
	"System:System Integrity", "System:IPsec Driver", "System:Other System Events",
	"Logon/Logoff:Logon", "Logon/Logoff:Logoff", "Logon/Logoff:Account Lockout",
	"Logon/Logoff:Special Logon", "Logon/Logoff:IPsec Main Mode",
	"Logon/Logoff:IPsec Quick Mode", "Logon/Logoff:IPsec Extended Mode",
	"Logon/Logoff:Other Logon/Logoff Events", "Logon/Logoff:Network Policy Server",
	"Logon/Logoff:User/Device Claims", "Logon/Logoff:Group Membership",
	"Object Access:File System", "Object Access:Registry",
	"Object Access:Kernel Object", "Object Access:SAM",
	"Object Access:Other Object Access Events",
	"Object Access:Certification Services", "Object Access:Application Generated",
	"Object Access:Handle Manipulation", "Object Access:File Share",
	"Object Access:Filtering Platform Packet Drop",
	"Object Access:Filtering Platform Connection",
	"Object Access:Detailed File Share", "Object Access:Removable Storage",
	"Object Access:Central Policy Staging",
	"Privilege Use:Sensitive Privilege Use", "Privilege Use:Non Sensitive Privilege Use",
	"Privilege Use:Other Privilege Use Events",
	"Detailed Tracking:Process Creation", "Detailed Tracking:Process Termination",
	"Detailed Tracking:DPAPI Activity", "Detailed Tracking:RPC Events",
	"Detailed Tracking:Plug and Play Events",
	"Detailed Tracking:Token Right Adjusted Events",
	"Policy Change:Audit Policy Change", "Policy Change:Authentication Policy Change",
	"Policy Change:Authorization Policy Change",
	"Policy Change:MPSSVC Rule-Level Policy Change",
	"Policy Change:Filtering Platform Policy Change",
	"Policy Change:Other Policy Change Events",
	"Account Management:User Account Management",
	"Account Management:Computer Account Management",
	"Account Management:Security Group Management",
	"Account Management:Distribution Group Management",
	"Account Management:Application Group Management",
	"Account Management:Other Account Management Events",
	"DS Access:Directory Service Access", "DS Access:Directory Service Changes",
	"DS Access:Directory Service Replication",
	"DS Access:Detailed Directory Service Replication",
	"Account Logon:Credential Validation",
	"Account Logon:Kerberos Service Ticket Operations",
	"Account Logon:Other Account Logon Events",
	"Account Logon:Kerberos Authentication Service",
}

// 版本分派:(数据长度, offset 8 处 u16 变体标识) → (版本标签, 类别表)
var auditVersions = map[[2]int]struct {
	label string
	cats  []string
}{
	{138, 0x78}: {"win7_2008", auditCatsWin7},
	{148, 0x82}: {"win10_early", auditCatsWin10},
	{150, 0x84}: {"win10_1607plus_2016_2022", auditCatsWin2016},
}

// auditSettings u16 值 → 设置标签(0=N 1=S 2=F 3=S/F;>3 留原值如实 note)。
var auditSettings = map[uint16]string{0: "N", 1: "S", 2: "F", 3: "S/F"}

// auditEntry 一条审计子类别。
type auditEntry struct {
	Category    string
	Subcategory string
	Value       uint16
	Setting     string
	HasSetting  bool // Value>3 → false,Setting 不置不猜
	Provisional bool
}

// parsePolAdtEv PolAdtEv 默认值 → (子类别, notes, 版本标签, provisional)。
// 12 字节头(variant=u16@8)+(len,variant) 查版本表;未知变体(如 Win11
// 152B/0x86):可用 u16 数 ≥ 共有类别数(59)时按共有前 59 类解且
// provisional=true + note,否则全不猜。
func parsePolAdtEv(raw []byte) ([]auditEntry, []string, string, bool) {
	var entries []auditEntry
	var notes []string
	if len(raw) < 12 {
		notes = append(notes, fmt.Sprintf("PolAdtEv 仅 %d 字节,不足 12 字节头,未解析",
			len(raw)))
		return entries, notes, "", false
	}
	variant := int(binary.LittleEndian.Uint16(raw[8:]))
	key := [2]int{len(raw), variant}
	provisional := false
	var version string
	var cats []string
	if kv, ok := auditVersions[key]; ok {
		version, cats = kv.label, kv.cats
	} else {
		version = fmt.Sprintf("unknown(len=%d,id=0x%x)", len(raw), variant)
		nAvail := (len(raw) - 12) / 2
		if nAvail >= len(auditCatsWin2016) {
			cats = auditCatsWin2016
			provisional = true
			notes = append(notes, fmt.Sprintf("PolAdtEv 变体未识别(长度 %d,"+
				"标识 0x%x;已知版本表止于 150B/0x84,152B/0x86 为 Win11 未知变体,"+
				"无公开 spec):仅按与 150B 版共有的前 %d 类解析并标 provisional,"+
				"尾部 %d 个 u16 不猜", len(raw), variant, len(cats),
				nAvail-len(cats)))
		} else {
			notes = append(notes, fmt.Sprintf("PolAdtEv 变体未识别(长度 %d,"+
				"标识 0x%x),可用 u16 仅 %d 个,不足共有类别数,全部不猜",
				len(raw), variant, nAvail))
			return entries, notes, version, false
		}
	}
	for i, cat := range cats {
		val := binary.LittleEndian.Uint16(raw[0x0C+2*i:])
		parts := strings.SplitN(cat, ":", 2)
		ent := auditEntry{Category: parts[0], Subcategory: parts[1],
			Value: val, Provisional: provisional}
		if setting, ok := auditSettings[val]; ok {
			ent.Setting, ent.HasSetting = setting, true
		} else {
			notes = append(notes, fmt.Sprintf("子类别 %s 值 %d 超出 0-3,留原值不猜",
				cat, val))
		}
		entries = append(entries, ent)
	}
	return entries, notes, version, provisional
}

// ---- LUID → Se*Privilege(MS-LSAD Privilege Data Model 官方常量表,照抄树庭) ----
var luidPrivilege = map[uint64]string{
	2: "SeCreateTokenPrivilege", 3: "SeAssignPrimaryTokenPrivilege",
	4: "SeLockMemoryPrivilege", 5: "SeIncreaseQuotaPrivilege",
	6: "SeUnsolicitedInputPrivilege", 7: "SeTcbPrivilege",
	8: "SeSecurityPrivilege", 9: "SeTakeOwnershipPrivilege",
	10: "SeLoadDriverPrivilege", 11: "SeSystemProfilePrivilege",
	12: "SeSystemtimePrivilege", 13: "SeProfileSingleProcessPrivilege",
	14: "SeIncreaseBasePriorityPrivilege", 15: "SeCreatePagefilePrivilege",
	16: "SeCreatePermanentPrivilege", 17: "SeBackupPrivilege",
	18: "SeRestorePrivilege", 19: "SeShutdownPrivilege",
	20: "SeDebugPrivilege", 21: "SeAuditPrivilege",
	22: "SeSystemEnvironmentPrivilege", 23: "SeChangeNotifyPrivilege",
	24: "SeRemoteShutdownPrivilege", 25: "SeUndockPrivilege",
	26: "SeSyncAgentPrivilege", 27: "SeEnableDelegationPrivilege",
	28: "SeManageVolumePrivilege", 29: "SeImpersonatePrivilege",
	30: "SeCreateGlobalPrivilege", 31: "SeTrustedCredManAccessPrivilege",
	32: "SeRelabelPrivilege", 33: "SeIncreaseWorkingSetPrivilege",
	34: "SeTimeZonePrivilege", 35: "SeCreateSymbolicLinkPrivilege",
	36: "SeDelegateSessionUserImpersonatePrivilege",
}

// privEntry 一条权限分配。
type privEntry struct {
	Position       int
	LUID           uint64
	Name           string
	HasName        bool // 未知 LUID → false,留数字不猜
	Attr           uint32
	EnabledDefault bool // attr & 1 = 默认启用(RegRipper lsa 解释)
}

// parsePrivilgs Privilgs 默认值 → (权限条目, notes)。
// 布局(RegRipper lsa spec):u32 计数 + u32 pad + N×(LUID u64 + attr u32);
// 声明计数越界 → 截断如实记。
func parsePrivilgs(raw []byte) ([]privEntry, []string) {
	var entries []privEntry
	var notes []string
	if len(raw) < 8 {
		notes = append(notes, fmt.Sprintf("Privilgs 仅 %d 字节,不足 8 字节头,未解析",
			len(raw)))
		return entries, notes
	}
	count := int(binary.LittleEndian.Uint32(raw))
	avail := (len(raw) - 8) / 12
	if count > avail {
		notes = append(notes, fmt.Sprintf("Privilgs 声明 %d 条,实际仅容 %d 条"+
			"(blob %d 字节),截断如实记", count, avail, len(raw)))
		count = avail
	}
	for i := 0; i < count; i++ {
		luid := binary.LittleEndian.Uint64(raw[8+12*i:])
		attr := binary.LittleEndian.Uint32(raw[8+12*i+8:])
		ent := privEntry{Position: i, LUID: luid, Attr: attr,
			EnabledDefault: attr&0x1 != 0}
		if name, ok := luidPrivilege[luid]; ok {
			ent.Name, ent.HasName = name, true
		} else {
			notes = append(notes, fmt.Sprintf("LUID %d 不在 MS-LSAD 名称表(2-36),"+
				"留数字不猜", luid))
		}
		entries = append(entries, ent)
	}
	return entries, notes
}

// ==================== ShimcacheHiveParser(SYSTEM hive) ====================

// ShimcacheHiveParser SYSTEM hive → shimcache_entry_full 事件流。
type ShimcacheHiveParser struct{}

// Records 打开 SYSTEM hive,遍历 root 下 ControlSetNNN 子键逐 CS 解
// AppCompatCache 值;非 regf/打不开 → 文件级如实 failed。
func (ShimcacheHiveParser) Records(path string) (Stream, error) {
	f, _, root, err := openTopicHive(path)
	if err != nil {
		return nil, err
	}
	s := &topicStream{f: f}
	var notes []string
	var controlsets []string
	for _, sk := range root.Subkeys() {
		if name := hiveKeyName(sk); controlSetRe.MatchString(name) {
			controlsets = append(controlsets, name)
		}
	}
	if len(controlsets) == 0 {
		notes = append(notes, "未发现 ControlSet* 子键,无 Shimcache 可解")
	}
	sort.Strings(controlsets) // 树庭 sorted(controlsets) 同款定序
	entries := 0
	for _, cs := range controlsets {
		acc := openKeyPath(root, cs+`\Control\Session Manager\AppCompatCache`)
		if acc == nil {
			notes = append(notes, cs+` Control\Session Manager\AppCompatCache `+
				"键不存在,该 ControlSet 无 Shimcache")
			continue
		}
		cv := findHiveValue(acc, "AppCompatCache")
		if cv == nil {
			notes = append(notes, cs+" AppCompatCache 值不存在,该 ControlSet 跳过")
			continue
		}
		blob, ok := hiveValueBytes(cv)
		if !ok {
			notes = append(notes, fmt.Sprintf("%s AppCompatCache 值非字节串"+
				"(%s),不猜", cs, cv.TypeString()))
			continue
		}
		ents, bnotes := parseShimcacheBlob(blob)
		for _, n := range bnotes {
			notes = append(notes, cs+" Shimcache: "+n)
		}
		for _, ent := range ents {
			s.recs = append(s.recs, shimcacheRecord(len(s.recs)+1, cs, ent))
			entries++
		}
	}
	sum := topicSummaryRecord("shimcache",
		map[string]int{"shimcache_entry_full": entries}, notes,
		map[string]any{
			"controlsets_seen": controlsets,
			"note": "魔数全不认识的 ControlSet 记 0 条 + notes 如实记(树庭同款," +
				"不文件级 failed);条目上限 100000 防结构错位",
		})
	sum.LineNo = len(s.recs) + 1
	s.recs = append(s.recs, sum)
	return s, nil
}

// shimcacheRecord 一条目 → shimcache_entry_full 事件;
// ts = last_modified(FILETIME 原生 UTC)TsUTCDirect 直通。
func shimcacheRecord(lineNo int, cs string, ent shimEntry) model.Record {
	norm := map[string]any{
		"event_type": "shimcache_entry_full",
		"source":     "shimcache_hive_binary",
		"controlset": cs,
		"position":   ent.Position,
		"path":       ent.Path,
		"crc32":      ent.CRC32,
		"entry_len":  ent.EntryLen,
		"win_ver":    ent.WinVer,
		// 文案纪律(硬要求,照树庭):时间戳是文件最后修改时间,不是执行时间;
		// Shimcache 出现不证明执行。
		"note": "二进制完整版(Mandiant spec);时间戳是文件最后修改时间,不是执行" +
			"时间;Shimcache 出现不证明执行;与 shimcache.py 的 REG_*.txt 字符串" +
			"提取版(exec_trace)并存",
	}
	if ent.HasExec {
		norm["exec_flag"] = ent.ExecFlag // Win10 无此字段 → 不置
	}
	var ts *time.Time
	if ent.LastModOK {
		t, _ := FiletimeToUTC(ent.LastModFT)
		norm["last_modified_utc"] = t.Format("2006-01-02T15:04:05Z")
		ts = &t
	}
	return model.Record{LineNo: lineNo, Kind: model.KindEvent, Norm: norm,
		Raw:         fmt.Sprintf("%s/AppCompatCache/#%d", cs, ent.Position),
		TsUTCDirect: ts}
}

// ==================== SamAccountsParser(SAM hive) ====================

// SamAccountsParser SAM hive → sam_account 事件流。
type SamAccountsParser struct{}

// Records 打开 SAM hive:SAM\Domains\Account 的 V 值末 24 字节 → 机器 SID;
// Users 下 8 位十六进制名子键逐账户解 F/V。非 regf → 文件级如实 failed。
func (SamAccountsParser) Records(path string) (Stream, error) {
	f, _, root, err := openTopicHive(path)
	if err != nil {
		return nil, err
	}
	s := &topicStream{f: f}
	var notes []string
	machineSID := ""
	if dom := openKeyPath(root, `SAM\Domains\Account`); dom == nil {
		notes = append(notes, `SAM\Domains\Account 键不存在,机器 SID 未取,`+
			"账户 sid 字段退化为缺省")
	} else if cv := findHiveValue(dom, "V"); cv == nil {
		notes = append(notes, `SAM\Domains\Account 无 V 值,机器 SID 未取`)
	} else if vb, ok := hiveValueBytes(cv); !ok {
		notes = append(notes, `SAM\Domains\Account 的 V 非字节串,机器 SID 未取不猜`)
	} else {
		sid, note := machineSIDFromAccountV(vb)
		if note != "" {
			notes = append(notes, "机器 SID: "+note)
		}
		machineSID = sid
	}

	accounts := 0
	users := openKeyPath(root, `SAM\Domains\Account\Users`)
	if users == nil {
		notes = append(notes, `SAM\Domains\Account\Users 键打开失败(不存在),`+
			"0 账户")
	} else {
		for _, uk := range users.Subkeys() {
			kname := hiveKeyName(uk)
			if !ridKeyRe.MatchString(kname) {
				continue // Names 等辅助键跳过(非 RID 键)
			}
			fv := findHiveValue(uk, "F")
			vv := findHiveValue(uk, "V")
			if fv == nil || vv == nil {
				notes = append(notes, fmt.Sprintf("Users\\%s 缺 F 或 V 值,"+
					"该账户跳过不猜", kname))
				continue
			}
			fb, fok := hiveValueBytes(fv)
			vb, vok := hiveValueBytes(vv)
			if !fok || !vok {
				notes = append(notes, fmt.Sprintf("Users\\%s 的 F/V 非字节串,"+
					"该账户跳过不猜", kname))
				continue
			}
			fv2, anotes := parseSamFV(fb, vb)
			for _, n := range anotes {
				notes = append(notes, fmt.Sprintf("Users\\%s: %s", kname, n))
			}
			s.recs = append(s.recs,
				samAccountRecord(len(s.recs)+1, kname, machineSID, fv2))
			accounts++
		}
		if accounts == 0 {
			notes = append(notes, "Users 键下无 RID 子键,0 账户(结构异常如实记)")
		}
	}
	extra := map[string]any{}
	if machineSID != "" {
		extra["machine_sid"] = machineSID
	}
	sum := topicSummaryRecord("sam", map[string]int{"sam_account": accounts},
		notes, extra)
	sum.LineNo = len(s.recs) + 1
	s.recs = append(s.recs, sum)
	return s, nil
}

// samAccountRecord 一个 RID 子键 → sam_account 事件;
// ts = password_last_set(FILETIME 原生 UTC)TsUTCDirect 直通。
func samAccountRecord(lineNo int, keyName, machineSID string,
	fv samFV) model.Record {

	rid := int(fv.RID)
	if !fv.HasF || rid == 0 {
		// F 不足长(或 RID 槽为 0)→ 退回键名十六进制(树庭同款兜底)
		if n, err := strconv.ParseUint(keyName, 16, 32); err == nil {
			rid = int(n)
		}
	}
	norm := map[string]any{
		"event_type": "sam_account",
		"rid":        rid,
		"note":       "SAM hive F/V 值按 RegRipper samparse spec 解析",
	}
	if machineSID != "" {
		norm["machine_sid"] = machineSID
		norm["sid"] = fmt.Sprintf("%s-%d", machineSID, rid)
	}
	if fv.HasUsername {
		norm["username"] = fv.Username
	}
	if fv.HasFullname {
		norm["fullname"] = fv.Fullname
	}
	if fv.HasComment {
		norm["comment"] = fv.Comment
	}
	var ts *time.Time
	if fv.HasF {
		putFT(norm, "last_logon_utc", fv.LastLogonFT)
		if t, ok := FiletimeToUTC(fv.PwdLastSetFT); ok {
			norm["password_last_set_utc"] = t.Format("2006-01-02T15:04:05Z")
			ts = &t
		}
		putFT(norm, "account_expires_utc", fv.AcctExpiresFT)
		putFT(norm, "last_failed_logon_utc", fv.LastFailFT)
		norm["acb_flags"] = fv.ACB
		decoded := []string{}
		for _, b := range samACBBits {
			if fv.ACB&b.bit != 0 {
				decoded = append(decoded, b.label)
			}
		}
		norm["acb_decoded"] = decoded
		norm["disabled"] = fv.ACB&0x0001 != 0
		norm["bad_password_count"] = fv.BadPwdCount
		norm["login_count"] = fv.LoginCount
	}
	return model.Record{LineNo: lineNo, Kind: model.KindEvent, Norm: norm,
		Raw: "SAM/Domains/Account/Users/" + keyName, TsUTCDirect: ts}
}

// putFT FILETIME → *_utc ISO 留证;非法 → 字段不置(不猜)。
func putFT(norm map[string]any, field string, ft uint64) {
	if t, ok := FiletimeToUTC(ft); ok {
		norm[field] = t.Format("2006-01-02T15:04:05Z")
	}
}

// ==================== SecurityPolicyParser(SECURITY hive) ====================

// SecurityPolicyParser SECURITY hive → security_domain_info /
// security_audit_policy / security_privilege 事件流。
//
// 原则性不碰(凭据材料纪律,测试焊死):不 open Policy\Secrets、PolEKList、
// PolOldSyskey、SecDesc;Cache\NL$n 只数 vk 声明尺寸,内容一个字节不解。
type SecurityPolicyParser struct{}

// Records 打开 SECURITY hive 解明文政策三件半;非 regf → 文件级如实 failed。
func (SecurityPolicyParser) Records(path string) (Stream, error) {
	f, _, root, err := openTopicHive(path)
	if err != nil {
		return nil, err
	}
	s := &topicStream{f: f}
	var notes []string
	counts := map[string]int{"security_domain_info": 0,
		"security_audit_policy": 0, "security_privilege": 0}

	pol := openKeyPath(root, "Policy")
	if pol == nil {
		notes = append(notes, "Policy 键打开失败(不存在),SECURITY 明文政策全部未解")
		sum := topicSummaryRecord("security", counts, notes, nil)
		sum.LineNo = 1
		s.recs = append(s.recs, sum)
		return s, nil
	}

	// ---- ① 域/机器身份 + ④ Cache 槽位计数(并入同一事件) ----
	s.recs = append(s.recs, s.domainInfoRecord(root, pol, &notes))
	counts["security_domain_info"] = 1

	// ---- ② 审计策略 ----
	counts["security_audit_policy"] = s.emitAuditPolicy(pol, &notes)

	// ---- ③ 权限分配 ----
	counts["security_privilege"] = s.emitPrivileges(pol, &notes)

	sum := topicSummaryRecord("security", counts, notes, map[string]any{
		"note": "SECURITY 只解明文政策三件半(域身份/审计策略/权限/Cache 槽位," +
			"RegRipper polacdmn+auditpol+lsa 与 MS-LSAD spec);Secrets/" +
			"PolEKList/PolOldSyskey/SecDesc/NL$n 内容原则性不碰(凭据材料," +
			"非静默缺口)",
	})
	sum.LineNo = len(s.recs) + 1
	s.recs = append(s.recs, sum)
	return s, nil
}

// domainInfoRecord ①+④ → security_domain_info 事件;
// ts = Policy 键 last-write(原生 UTC)直通。
func (s *topicStream) domainInfoRecord(root, pol *regparser.CM_KEY_NODE,
	notes *[]string) model.Record {

	norm := map[string]any{"event_type": "security_domain_info"}
	for _, kp := range []struct {
		field, key string
	}{{"account_domain_name", "PolAcDmN"}, {"primary_domain_name", "PolPrDmN"},
		{"dns_domain_name", "PolDnDDN"}, {"dns_tree_name", "PolDnTrN"}} {
		sub := openKeyPath(pol, kp.key)
		if sub == nil {
			continue // 键不存在(版本差异)字段缺省,不猜
		}
		raw, _ := defaultHiveBytes(sub)
		val, ok, note := parseUnicodeStringBlob(raw)
		if note != "" {
			*notes = append(*notes, fmt.Sprintf(`Policy\%s: %s`, kp.key, note))
		}
		if ok {
			norm[kp.field] = val
		}
	}
	for _, kp := range []struct {
		field, key string
	}{{"account_domain_sid", "PolAcDmS"}, {"primary_domain_sid", "PolPrDmS"}} {
		sub := openKeyPath(pol, kp.key)
		if sub == nil {
			continue
		}
		raw, ok := defaultHiveBytes(sub)
		if !ok || len(raw) == 0 {
			continue // 空值=工作组机,如实缺省
		}
		sid := decodeBinarySID(raw)
		if sid == "" {
			*notes = append(*notes, fmt.Sprintf(`Policy\%s: %d 字节不是合法`+
				"二进制 SID 结构,不猜", kp.key, len(raw)))
			continue
		}
		norm[kp.field] = sid
	}
	if sub := openKeyPath(pol, "PolDnDmG"); sub != nil {
		raw, _ := defaultHiveBytes(sub)
		guid, ok, note := parseGuidBlob(raw)
		if note != "" {
			*notes = append(*notes, "Policy\\PolDnDmG: "+note)
		}
		if ok {
			norm["domain_guid"] = guid
		}
	}
	_, hasDNS := norm["dns_domain_name"]
	_, hasPrimSID := norm["primary_domain_sid"]
	norm["domain_joined"] = hasDNS || hasPrimSID
	norm["domain_joined_basis"] = "判据:PolDnDDN 或 PolPrDmS 非空(域机才有," +
		"工作组机两者皆空);非系统API结论,如实留据"

	// Cache 槽位:只数 NL$Control 存在性与 NL$1..NL$10 值存在数/声明尺寸>0 数
	// (vk.DataLength,凭据材料纪律:NL$n 内容一个字节不解,不调 ValueData)。
	if cache := openKeyPath(root, "Cache"); cache == nil {
		*notes = append(*notes, "Cache 键不存在,槽位未数")
	} else {
		slots, nonempty := 0, 0
		controlPresent := false
		for _, v := range cache.Values() {
			name := hiveValueName(v)
			if strings.EqualFold(name, "NL$Control") {
				controlPresent = true
				continue
			}
			if cacheSlotRe.MatchString(name) {
				slots++
				if v.DataSize() > 0 { // 声明尺寸,不触内容
					nonempty++
				}
			}
		}
		norm["cached_logon"] = map[string]any{
			"nl_control_present": controlPresent,
			"slots_present":      slots,
			"slots_nonempty":     nonempty,
			"note": "只数值存在数与尺寸>0数,NL$n 内容一个字节不解(凭据材料原则);" +
				"非空槽位=机器曾有域缓存登录的判据;槽位为定长结构,尺寸判据不区分" +
				"全零槽,边界如实标注",
		}
	}
	norm["note"] = "SECURITY 明文政策(RegRipper polacdmn spec);" +
		"Secrets/PolEKList/PolOldSyskey/SecDesc 原则性不碰(凭据材料)"
	rec := model.Record{LineNo: len(s.recs) + 1, Kind: model.KindEvent,
		Norm: norm, Raw: "Policy"}
	if t, iso := keyLastWrite(pol); t != nil {
		norm["policy_key_last_write_utc"] = iso
		rec.TsUTCDirect = t
	}
	return rec
}

// emitAuditPolicy ② PolAdtEv → security_audit_policy 事件(0 或 1 条);
// ts = PolAdtEv 键 last-write 直通。
func (s *topicStream) emitAuditPolicy(pol *regparser.CM_KEY_NODE,
	notes *[]string) int {

	adt := openKeyPath(pol, "PolAdtEv")
	if adt == nil {
		*notes = append(*notes, `Policy\PolAdtEv 不存在,审计策略未解`)
		return 0
	}
	raw, ok := defaultHiveBytes(adt)
	if !ok {
		*notes = append(*notes, `Policy\PolAdtEv 无字节串默认值,审计策略未解`)
		return 0
	}
	entries, anotes, version, provisional := parsePolAdtEv(raw)
	for _, n := range anotes {
		*notes = append(*notes, "PolAdtEv: "+n)
	}
	if len(entries) == 0 {
		return 0
	}
	subs := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		m := map[string]any{
			"category":    e.Category,
			"subcategory": e.Subcategory,
			"value":       e.Value,
		}
		if e.HasSetting {
			m["setting"] = e.Setting
		}
		if e.Provisional {
			m["provisional"] = true
		}
		subs = append(subs, m)
	}
	norm := map[string]any{
		"event_type":          "security_audit_policy",
		"version":             version,
		"provisional":         provisional,
		"data_len":            len(raw),
		"variant_id":          fmt.Sprintf("0x%x", binary.LittleEndian.Uint16(raw[8:])),
		"subcategories":       subs,
		"subcategories_count": len(subs),
		"settings_legend":     "0=N(无) 1=S(成功) 2=F(失败) 3=S/F",
		"note": "子类别顺序表照 RegRipper auditpol.pl 版本表;" +
			"provisional=true 表示未知变体按共有前缀解析,待 spec",
	}
	rec := model.Record{LineNo: len(s.recs) + 1, Kind: model.KindEvent,
		Norm: norm, Raw: "Policy/PolAdtEv"}
	if t, iso := keyLastWrite(adt); t != nil {
		norm["key_last_write_utc"] = iso
		rec.TsUTCDirect = t
	}
	s.recs = append(s.recs, rec)
	return 1
}

// emitPrivileges ③ Policy\Accounts\<SID>\Privilgs → 每条一
// security_privilege 事件;ts = Privilgs 键 last-write 直通。
func (s *topicStream) emitPrivileges(pol *regparser.CM_KEY_NODE,
	notes *[]string) int {

	accounts := openKeyPath(pol, "Accounts")
	if accounts == nil {
		*notes = append(*notes, `Policy\Accounts 打开失败(不存在),`+
			"权限分配未解")
		return 0
	}
	n := 0
	for _, sk := range accounts.Subkeys() {
		sidName := hiveKeyName(sk)
		if !accountSIDRe.MatchString(sidName) {
			continue // 非 SID 子键跳过(非权限主体)
		}
		privKey := openKeyPath(sk, "Privilgs")
		if privKey == nil {
			continue // 无 Privilgs 属正常(无特权授予),不记警示(树庭同款)
		}
		raw, ok := defaultHiveBytes(privKey)
		if !ok {
			*notes = append(*notes, fmt.Sprintf(`Accounts\%s\Privilgs 无字节串`+
				"默认值,跳过", sidName))
			continue
		}
		entries, pnotes := parsePrivilgs(raw)
		for _, pn := range pnotes {
			*notes = append(*notes, fmt.Sprintf(`Accounts\%s: %s`, sidName, pn))
		}
		lwT, lwISO := keyLastWrite(privKey)
		for _, e := range entries {
			norm := map[string]any{
				"event_type":           "security_privilege",
				"sid":                  sidName,
				"luid":                 e.LUID,
				"attr":                 e.Attr,
				"attr_enabled_default": e.EnabledDefault,
				"position":             e.Position,
				"note": "LUID 名称表按 MS-LSAD Privilege Data Model;" +
					"attr&1=默认启用(RegRipper lsa 解释),attr 原值同留",
			}
			if e.HasName {
				norm["privilege_name"] = e.Name // 未知 LUID 留数字不猜
			}
			rec := model.Record{LineNo: len(s.recs) + 1, Kind: model.KindEvent,
				Norm: norm,
				Raw: fmt.Sprintf("Policy/Accounts/%s/Privilgs/#%d", sidName,
					e.Position)}
			if lwT != nil {
				norm["key_last_write_utc"] = lwISO
				rec.TsUTCDirect = lwT
			}
			s.recs = append(s.recs, rec)
			n++
		}
	}
	return n
}
