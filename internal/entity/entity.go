// Package entity 实体层:从已解析事件里抽实体(IP/domain/account/file_hash),
// 归一成 canonical_key 落 PG,供签名规则(target: entity)与跨机聚合引用。
//
// 语义基准 = 树庭 backend/app/entities.py(§8.2/§9.2 canonical_key 与
// qualifier 语义逐条对齐):
//
//   - 每个实体产出 (canonical_key, qualifier);保守默认主机限定
//     (host_scoped),只有全局唯一身份才 qualifier=global 允许跨机合并;
//   - IP:公网 → ip:<addr> global;私网/回环/链路本地 → ip:<addr>@<host>
//     host_scoped(私网永不进跨机匹配,防「每台 192.168.x 假联动」);
//     未指定(0.0.0.0/::)/组播不是「一台机器」的身份,不抽;
//     公网判定与算子侧 publicIP(internal/operator/cross.go)同一口径
//     (netip 结构判定;Python is_global 还排除 CGNAT/保留段,Go netip
//     无等价 API,差异如实标注);
//   - domain:小写、去尾点、FQDN 结构校验 → dom:<fqdn> global;
//   - account:有 SID → acct:sid:<SID 大写> global;只有名 →
//     acct:name:<小写名>@<host> host_scoped;
//   - file_hash:64 位 hex 小写 → hash:sha256:<h> global(哈希即身份);
//   - 结构不合一律不抽(宁可少抽不造错键)。
//
// 归一化规则(用户拍板):IP 去端口、domain 小写去尾点、account 小写、
// hash 小写。
package entity

import (
	"encoding/json"
	"net/netip"
	"regexp"
	"strings"
)

// 实体类型(规则 match.entity_type 的词表)。
const (
	TypeIP       = "ip"
	TypeDomain   = "domain"
	TypeAccount  = "account"
	TypeFileHash = "file_hash"
)

// qualifier 词表:global = 全局唯一身份(可跨机聚合);host_scoped =
// 主机限定(私网 IP/无名账户;跨机聚合结构性排除)。
const (
	QualGlobal     = "global"
	QualHostScoped = "host_scoped"
)

var (
	sidRe    = regexp.MustCompile(`^S-\d+-\d+(?:-\d+)+$`)
	fqdnRe   = regexp.MustCompile(
		`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Row 实体表一行(entities 表的行投影;证据锚点 = host + source_id +
// line_no,源行 sha256 在 sources 表)。
type Row struct {
	CaseID       string `json:"case_id"`
	Host         string `json:"host"`
	EntityType   string `json:"entity_type"`
	RawValue     string `json:"raw_value"`     // 原始值(留证)
	CanonicalKey string `json:"canonical_key"` // 归一键(跨源/跨机比对键)
	Qualifier    string `json:"qualifier"`     // global | host_scoped
	SourceID     string `json:"source_id"`
	LineNo       int    `json:"line_no"`
}

// Cand 抽取候选(未锚定 case/source/line;由管线补锚)。
type Cand struct {
	EntityType   string
	RawValue     string
	CanonicalKey string
	Qualifier    string
}

// isPublicIP 公网判定(与 operator.cross.go publicIP 同一口径:结构性排除
// 私网/回环/链路本地/组播/未指定——协议结构判定,不碰案件值)。
func isPublicIP(addr netip.Addr) bool {
	return !(addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified())
}

// IPKey IP 实体归一:去端口(带端口形态先拆)、公网 → global,私网等 →
// host_scoped(@host 后缀);未指定/组播/判不出 → 不抽。
func IPKey(raw, host string) (Cand, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || s == "-" {
		return Cand{}, false
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		// 去端口:host:port 与 [v6]:port 形态(netstat 之外的源字段可能带)
		if ap, err2 := netip.ParseAddrPort(s); err2 == nil {
			addr = ap.Addr()
		} else {
			return Cand{}, false
		}
	}
	text := addr.String()
	// 未指定(0.0.0.0/::)/组播/受限广播(255.255.255.255,RFC 919 协议
	// 常量)不是「一台机器」的身份 → 不抽(树庭 ip_key 同语义;Go netip
	// 无 is_reserved API,受限广播单列)。
	if addr.IsUnspecified() || addr.IsMulticast() ||
		addr.Compare(netip.MustParseAddr("255.255.255.255")) == 0 {
		return Cand{}, false
	}
	if !isPublicIP(addr) {
		return Cand{EntityType: TypeIP, RawValue: s,
			CanonicalKey: "ip:" + text + "@" + host, Qualifier: QualHostScoped}, true
	}
	return Cand{EntityType: TypeIP, RawValue: s,
		CanonicalKey: "ip:" + text, Qualifier: QualGlobal}, true
}

// DomainKey 域名实体归一:小写、去尾点、FQDN 结构校验;结构不合 → 不抽。
func DomainKey(raw string) (Cand, bool) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if name == "" || len(name) > 253 || !fqdnRe.MatchString(name) {
		return Cand{}, false
	}
	return Cand{EntityType: TypeDomain, RawValue: strings.TrimSpace(raw),
		CanonicalKey: "dom:" + name, Qualifier: QualGlobal}, true
}

// AccountKey 账户实体归一:SID 优先(global 身份);无名无 SID → 不抽。
func AccountKey(name, sid, host string) (Cand, bool) {
	if s := strings.ToUpper(strings.TrimSpace(sid)); sidRe.MatchString(s) {
		return Cand{EntityType: TypeAccount, RawValue: s,
			CanonicalKey: "acct:sid:" + s, Qualifier: QualGlobal}, true
	}
	if n := strings.ToLower(strings.TrimSpace(name)); n != "" && n != "-" {
		return Cand{EntityType: TypeAccount, RawValue: strings.TrimSpace(name),
			CanonicalKey: "acct:name:" + n + "@" + host, Qualifier: QualHostScoped}, true
	}
	return Cand{}, false
}

// HashKey 文件哈希实体归一:64 位 hex 小写(哈希即身份,global)。
func HashKey(raw string) (Cand, bool) {
	h := strings.ToLower(strings.TrimSpace(raw))
	if !sha256Re.MatchString(h) {
		return Cand{}, false
	}
	return Cand{EntityType: TypeFileHash, RawValue: h,
		CanonicalKey: "hash:sha256:" + h, Qualifier: QualGlobal}, true
}

// 取值字段词表(对事件 fields JSON 取;顶层没有再看 data 子对象一层——
// 与算子侧 dataStr 同口径)。新增字段是数据工作,改这里。
var (
	ipFields      = []string{"src_ip", "ip", "local_addr", "remote_addr", "IpAddress", "SourceNetworkAddress"}
	domainFields  = []string{"domain"}
	sidFields     = []string{"SubjectUserSid", "TargetUserSid", "MemberSid", "user_sid", "sid"}
	accountFields = []string{"account", "user", "SubjectUserName", "TargetUserName"}
	sha256Fields  = []string{"sha256", "file_sha256", "SHA256", "hash_sha256"}
)

// fieldStr 顶层取值 → data 子对象一层兜底(evtx EventData)。
func fieldStr(fields map[string]any, key string) string {
	if v, ok := fields[key].(string); ok && v != "" {
		return v
	}
	if sub, ok := fields["data"].(map[string]any); ok {
		if v, ok := sub[key].(string); ok {
			return v
		}
	}
	return ""
}

// Extract 从一条事件的 fields JSON 抽实体候选(同键同事件内去重;
// 结构不合/私有占位一律不抽,宁缺毋滥)。fields JSON 坏 → 空,不炸流。
func Extract(fieldsJSON string, host string) []Cand {
	if fieldsJSON == "" {
		return nil
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(fieldsJSON), &fields); err != nil {
		return nil
	}
	var out []Cand
	seen := map[string]bool{}
	push := func(c Cand, ok bool) {
		if !ok || seen[c.CanonicalKey] {
			return
		}
		seen[c.CanonicalKey] = true
		out = append(out, c)
	}
	for _, f := range ipFields {
		push(IPKey(fieldStr(fields, f), host))
	}
	for _, f := range domainFields {
		push(DomainKey(fieldStr(fields, f)))
	}
	var sid string
	for _, f := range sidFields {
		if v := fieldStr(fields, f); v != "" {
			sid = v
			break
		}
	}
	for _, f := range accountFields {
		push(AccountKey(fieldStr(fields, f), sid, host))
	}
	for _, f := range sha256Fields {
		push(HashKey(fieldStr(fields, f)))
	}
	return out
}
