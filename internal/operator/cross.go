// 跨层实体族算子(DESIGN §6.1:同实体跨源复现,唯一跨层族)。
//
// 同公网实体(IP)在 ≥N 个源出现 → 强疑似结构(N 个独立证据点 +
// 同实体咬合)。私网/回环/链路本地/组播一律结构性排除(netip 语义,
// 是协议结构不是案件值)——私网 IP 跨源复现是网络拓扑常态,不构证据。
//
// 每类源从哪些字段取实体是 spec 数据(params.ip_fields):
//
//	web_access:        [src_ip]
//	windows_event_log: [IpAddress, SourceNetworkAddress]
//
// 未声明的 log_type 不参与该算子(适用域路由已滤)。
package operator

import (
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/ye-mengwen/fengtu/internal/query"
)

type crossEntityMultiSource struct{}

type ipSourceStat struct {
	count     int
	firstLine int
	firstTS   *time.Time
}

// defaultIPFields 缺省取值字段(spec 可覆盖)。
var defaultIPFields = map[string][]string{
	"web_access":        {"src_ip"},
	"windows_event_log": {"IpAddress", "SourceNetworkAddress"},
}

func (crossEntityMultiSource) ipFields(spec *Spec) (map[string][]string, error) {
	v, ok := spec.Params["ip_fields"]
	if !ok {
		return defaultIPFields, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errParam(spec, "ip_fields 须为 {log_type: [字段,...]}")
	}
	out := map[string][]string{}
	for lt, fv := range m {
		list, ok := fv.([]any)
		if !ok || len(list) == 0 {
			return nil, errParam(spec, "ip_fields."+lt+" 须为非空字符串列表")
		}
		for _, e := range list {
			s, ok := e.(string)
			if !ok {
				return nil, errParam(spec, "ip_fields."+lt+" 须为非空字符串列表")
			}
			out[lt] = append(out[lt], s)
		}
	}
	return out, nil
}

func errParam(spec *Spec, msg string) error {
	return &paramError{op: spec.ID, msg: msg}
}

type paramError struct{ op, msg string }

func (e *paramError) Error() string { return "算子 " + e.op + " 参数非法: " + e.msg }

// publicIP 结构性排除:私网/回环/链路本地/组播/未指定都不是公网证据。
func publicIP(s string) (string, bool) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return "", false
	}
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return "", false
	}
	return addr.String(), true
}

func (crossEntityMultiSource) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	minSources, err := intParam(spec, "min_sources", 2)
	if err != nil {
		return nil, err
	}
	if minSources < 2 {
		minSources = 2
	}
	ipFields, err := crossEntityMultiSource{}.ipFields(spec)
	if err != nil {
		return nil, err
	}

	type ipAgg struct {
		sources map[string]*ipSourceStat
	}
	aggs := map[string]*ipAgg{}
	for _, src := range srcs {
		fields := ipFields[src.LogType]
		if len(fields) == 0 {
			continue // 该品类未声明取值字段,不参与(适用域语义,如实跳过)
		}
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			for _, key := range fields {
				raw := dataStr(f, key)
				if raw == "" || raw == "-" || raw == "::1" {
					continue
				}
				ip, ok := publicIP(raw)
				if !ok {
					continue
				}
				agg := aggs[ip]
				if agg == nil {
					agg = &ipAgg{sources: map[string]*ipSourceStat{}}
					aggs[ip] = agg
				}
				st := agg.sources[src.ID]
				if st == nil {
					st = &ipSourceStat{firstLine: ev.LineNo, firstTS: ev.TS}
					agg.sources[src.ID] = st
				}
				st.count++
				break // 一个事件一个实体账(多字段命中同一 IP 不重复计)
			}
			return nil
		})
		if serr != nil {
			return nil, serr
		}
	}

	var out []Finding
	for ip, agg := range aggs {
		if len(agg.sources) < minSources {
			continue
		}
		// 锚点:最早出现的源+行(firstTS 可比则比 ts,否则比行号)
		anchorSrc, anchorLine := "", 0
		var anchorTS *time.Time
		var srcList []map[string]any
		for sid, st := range agg.sources {
			srcList = append(srcList, map[string]any{
				"source_id": sid, "count": st.count, "first_line": st.firstLine,
			})
			if anchorSrc == "" || earlier(st.firstTS, st.firstLine, anchorTS, anchorLine) {
				anchorSrc, anchorLine, anchorTS = sid, st.firstLine, st.firstTS
			}
		}
		out = append(out, Finding{
			SourceID: anchorSrc, LineNo: anchorLine, TS: anchorTS,
			MatchedField: "entity", MatchedValue: ip,
			Detail: map[string]any{
				"ip": ip, "source_count": len(agg.sources), "sources": srcList,
				"judgement_hint": "先查 IP 归属与方向——公网 IP 跨源复现只说明「有交集」," +
					"出入方向与各源语义要人读",
			},
			Evidence: Evidence{
				IndependentPoints: len(agg.sources), ChainLinked: true,
			},
		})
	}
	return out, nil
}

// ---- 跨主机实体(§6.1 升格:同实体 ≥2 主机为跨机案核心算子) ----

// crossHostEntity 同实体在 ≥min_hosts 台主机复现 → 跨机案核心信号。
// 实体类型走 params.entity_type(0.21.0-operator-port,对齐树庭跨主机三规
// 则 semantics,对照表 §3.1):
//
//	ip(缺省):        公网 IP 跨机(勒索案凭据复用/同一 C2 多机外联);
//	                 私网/回环/链路本地/组播结构性排除(netip 协议结构)。
//	account_sid:     同一 SID 跨机(树庭 xhost-shared-account-sid:域账户
//	                 跨机本身正常,入侵排查中是共享账户聚合候选;S-1-5-18/19/20
//	                 等熟知 SID 必然同值,是结构性已知噪音,不硬塞排除语法,
//	                 待审一眼排除——与树庭同一处置)。
//	file_sha256:     同一 sha256 跨机(树庭 xhost-shared-file-hash:同一样本
//	                 多机落=已扩散,直接圈波及面)。
//
// 取值字段:ip 走 params.ip_fields(按 log_type);sid/sha256 走
// params.entity_fields(按 log_type,可配),缺省字段清单全域适用。
// 主机未建模(host="")的源不参与跨主机关联,账上如实记 skipped_unmodeled。
type crossHostEntity struct{}

type hostSourceStat struct {
	count     int
	firstLine int
	firstTS   *time.Time
}

// 缺省实体取值字段(entity_fields 未声明时全域适用;dataStr 顶层+data 兜底)。
var defaultEntityFields = map[string][]string{
	"account_sid": {"SubjectUserSid", "TargetUserSid", "MemberSid", "user_sid", "sid"},
	"file_sha256": {"sha256", "file_sha256", "SHA256", "hash_sha256"},
}

var (
	sidRe    = regexp.MustCompile(`^S-\d+(-\d+)+$`)
	sha256Re = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// normalizeEntity 实体值归一+结构校验(非法值不参与,不猜)。
func normalizeEntity(entityType, raw string) (string, bool) {
	switch entityType {
	case "account_sid":
		v := strings.ToUpper(strings.TrimSpace(raw))
		return v, sidRe.MatchString(v)
	case "file_sha256":
		v := strings.ToLower(strings.TrimSpace(raw))
		return v, sha256Re.MatchString(v)
	default: // ip
		return publicIP(raw)
	}
}

// entityFieldsOf 解析实体取值字段:ip 走 ip_fields(原有逻辑);
// sid/sha256 走 entity_fields(同形 {log_type: [字段,...]}),缺省 =
// defaultEntityFields 全域( nil 表示不按 log_type 过滤)。
func (crossHostEntity) entityFieldsOf(spec *Spec, entityType string) (map[string][]string, []string, error) {
	if entityType == "ip" {
		m, err := crossEntityMultiSource{}.ipFields(spec)
		return m, nil, err
	}
	v, ok := spec.Params["entity_fields"]
	if !ok {
		def := defaultEntityFields[entityType]
		if def == nil {
			return nil, nil, errParam(spec, "entity_type 须为 ip|account_sid|file_sha256")
		}
		return nil, def, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, nil, errParam(spec, "entity_fields 须为 {log_type: [字段,...]}")
	}
	out := map[string][]string{}
	for lt, fv := range m {
		list, ok := fv.([]any)
		if !ok || len(list) == 0 {
			return nil, nil, errParam(spec, "entity_fields."+lt+" 须为非空字符串列表")
		}
		for _, e := range list {
			s, ok := e.(string)
			if !ok {
				return nil, nil, errParam(spec, "entity_fields."+lt+" 须为非空字符串列表")
			}
			out[lt] = append(out[lt], s)
		}
	}
	return out, nil, nil
}

func (crossHostEntity) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	minHosts, err := intParam(spec, "min_hosts", 2)
	if err != nil {
		return nil, err
	}
	if minHosts < 2 {
		minHosts = 2
	}
	entityType, err := strParam(spec, "entity_type", "ip")
	if err != nil {
		return nil, err
	}
	fieldsByType, defaultFields, err := crossHostEntity{}.entityFieldsOf(spec, entityType)
	if err != nil {
		return nil, err
	}

	// entity → host → source → 账
	type hostAgg struct {
		sources map[string]*hostSourceStat
	}
	aggs := map[string]map[string]*hostAgg{}
	unmodeled := 0
	for _, src := range srcs {
		if src.Host == "" {
			unmodeled++
			continue // 主机未建模的源不参与跨主机关联(如实跳过)
		}
		fields := defaultFields
		if fieldsByType != nil {
			fields = fieldsByType[src.LogType]
			if len(fields) == 0 {
				continue // 该品类未声明取值字段,不参与(适用域语义,如实跳过)
			}
		}
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			for _, key := range fields {
				raw := dataStr(f, key)
				if raw == "" || raw == "-" || raw == "::1" {
					continue
				}
				val, ok := normalizeEntity(entityType, raw)
				if !ok {
					continue
				}
				hm := aggs[val]
				if hm == nil {
					hm = map[string]*hostAgg{}
					aggs[val] = hm
				}
				ha := hm[src.Host]
				if ha == nil {
					ha = &hostAgg{sources: map[string]*hostSourceStat{}}
					hm[src.Host] = ha
				}
				st := ha.sources[src.ID]
				if st == nil {
					st = &hostSourceStat{firstLine: ev.LineNo, firstTS: ev.TS}
					ha.sources[src.ID] = st
				}
				st.count++
				break // 一个事件一个实体账(多字段命中同一值不重复计)
			}
			return nil
		})
		if serr != nil {
			return nil, serr
		}
	}

	hints := map[string]string{
		"ip": "跨机复现是「有共同交集」的客观事实,方向要人读:" +
			"同一公网 IP 是多机共同外联(C2/更新服务器)还是共同被连" +
			"(扫描器/攻击源),查各源字段语义与出入方向",
		"account_sid": "同一 SID 跨机=共享账户多机使用候选:域账户/漫游账户跨机" +
			"本身正常,先核是否运维共用账户;S-1-5-18/19/20 等熟知 SID 必然同值," +
			"是结构性已知噪音,一眼排除;本机账户各机 SID 不同天然不误并",
		"file_sha256": "同一 sha256 跨机=同一样本多机落,提示已扩散:" +
			"先按哈希圈波及面(还有哪些主机有),再回溯首落机与落地路径",
	}

	var out []Finding
	for val, hm := range aggs {
		if len(hm) < minHosts {
			continue
		}
		// 锚点:全主机范围内最早出现的源+行
		anchorSrc, anchorLine := "", 0
		var anchorTS *time.Time
		var hostList []map[string]any
		totalEvents := 0
		for host, ha := range hm {
			var srcList []map[string]any
			for sid, st := range ha.sources {
				srcList = append(srcList, map[string]any{
					"source_id": sid, "count": st.count, "first_line": st.firstLine,
				})
				totalEvents += st.count
				if anchorSrc == "" || earlier(st.firstTS, st.firstLine, anchorTS, anchorLine) {
					anchorSrc, anchorLine, anchorTS = sid, st.firstLine, st.firstTS
				}
			}
			hostList = append(hostList, map[string]any{
				"host": host, "sources": srcList,
			})
		}
		out = append(out, Finding{
			SourceID: anchorSrc, LineNo: anchorLine, TS: anchorTS,
			MatchedField: "entity", MatchedValue: val,
			Detail: map[string]any{
				"entity_type": entityType, "entity": val,
				"host_count": len(hm), "hosts": hostList,
				"total_events":              totalEvents,
				"unmodeled_sources_skipped": unmodeled,
				"judgement_hint":            hints[entityType],
			},
			Evidence: Evidence{IndependentPoints: len(hm), ChainLinked: true},
		})
	}
	return out, nil
}

// earlier 两锚点孰早(ts 都可比则比 ts,否则比行号)。
func earlier(tsA *time.Time, lineA int, tsB *time.Time, lineB int) bool {
	if tsA != nil && tsB != nil {
		return tsA.Before(*tsB)
	}
	return lineA < lineB
}
