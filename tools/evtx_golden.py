#!/usr/bin/env python
"""evtx 逐事件金标准对照(与切片一 golden 同思路):
树庭 Python 侧(PyEvtxParser,evtx_dump 同一 Rust 核心)产出参照 JSONL,
与丰图 Go 原生解析(Velocidex/evtx,经 ftevtxdump 导出)逐事件对拍。

用法:
  # 1) 产出树庭参照
  evtx_golden.py ref <file.evtx> > ref.jsonl
  # 2) 对照(ftevtxdump 输出 vs 参照)
  evtx_golden.py diff <ref.jsonl> <go.jsonl>

对拍口径(照 backend/app/parsers/evtx_log.py):
  record_id / channel / event_id / computer / ts_utc(毫秒) /
  data(平铺 EventData,标量按 str() 归一——Velocidex 给数值型,
  PyEvtxParser 给字符串,语义同值,表示差异如实说明)。
"""
import json
import sys
from datetime import datetime, timezone


def flatten(node):
    """EventData/UserData 平铺(照树庭 _flatten_eventdata)。"""
    out = {}
    if not isinstance(node, dict):
        return out
    for k, v in node.items():
        if k.startswith("#"):
            continue
        if isinstance(v, dict):
            text = v.get("#text")
            out[k] = text if text is not None else json.dumps(
                v, ensure_ascii=False)
        elif isinstance(v, list):
            out[k] = json.dumps(v, ensure_ascii=False)
        else:
            out[k] = v
    return out


def event_id_of(system):
    v = system.get("EventID")
    if isinstance(v, dict):
        v = v.get("#text")
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def ref_events(path):
    from evtx import PyEvtxParser
    rows = []
    total = 0
    for rec in PyEvtxParser(path).records_json():
        total += 1
        try:
            record_id = int(rec.get("event_record_id") or total)
            ev = json.loads(rec["data"])
            system = ev.get("Event", {}).get("System", {})
        except (TypeError, ValueError, AttributeError, json.JSONDecodeError):
            rows.append({"line_no": total, "kind": "bad",
                         "data": {"reason": "json/record 解析失败"}})
            continue
        eid = event_id_of(system)
        if eid is None:
            rows.append({"line_no": total, "kind": "bad",
                         "data": {"reason": "EventID 非法"}})
            continue
        ts = None
        tc = (system.get("TimeCreated") or {}).get("#attributes") or {}
        st = tc.get("SystemTime")
        if isinstance(st, str):
            try:
                dt = datetime.fromisoformat(
                    st.replace("Z", "+00:00")).astimezone(timezone.utc)
                ts = dt.strftime("%Y-%m-%dT%H:%M:%S.") + \
                    f"{dt.microsecond // 1000:03d}Z"
            except ValueError:
                ts = None
        node = ev.get("Event", {})
        data = flatten(node.get("EventData"))
        if not data:
            data = flatten(node.get("UserData"))
        rows.append({
            "line_no": total, "kind": "event",
            "record_id": system.get("EventRecordID", record_id),
            "channel": system.get("Channel"),
            "event_id": eid,
            "ts_utc": ts,
            "computer": system.get("Computer"),
            "data": data,
        })
    return rows


def norm_scalar(v):
    """标量归一(语义同值,表示差异归一,已实测两族):

    - 数值表示:Velocidex 原生数值(999)vs PyEvtxParser XML 文本
      ("999" 或十六进制 "0x3e7")→ 统一十进制串;
    - 时间表示:binxml 时间型字段,Velocidex 给 unix 秒 float,
      PyEvtxParser 给 ISO 串 → 统一 ISO 毫秒串。
    表示差异本身如实记录于 internal/ingest/evtx.go。
    """
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, (int, float)):
        # 长整型 unix 秒(10 位以上带小数)= binxml 时间型 → ISO
        if isinstance(v, float) and v > 1e9:
            dt = datetime.fromtimestamp(v, tz=timezone.utc)
            return dt.strftime("%Y-%m-%dT%H:%M:%S.") + \
                f"{dt.microsecond // 1000:03d}Z"
        if isinstance(v, float) and v.is_integer():
            return str(int(v))
        return str(v)
    if isinstance(v, str):
        s = v.strip()
        if s.lower().startswith("0x"):
            try:
                return str(int(s, 16))
            except ValueError:
                return v
        # ISO 时间串(PyEvtxParser 时间型字段)→ 毫秒截断,与 float 侧对齐
        if len(s) >= 24 and s[4] == "-" and s[10] == "T" and s.endswith("Z"):
            return s[:23] + "Z"
        return v
    return json.dumps(v, ensure_ascii=False)


def norm_data(d):
    return {k: norm_scalar(v) for k, v in (d or {}).items()}


def ts_ms(ts):
    """ISO → 毫秒截断串,统一双边精度(DateTime64(3))。"""
    if ts is None:
        return None
    return ts[:23] + ("Z" if len(ts) >= 23 else "")


# 关键 EventData 字段清单(取证语义主干:登录/进程/服务/网络/账户)。
KEY_FIELDS = {
    "IpAddress", "IpPort", "WorkstationName", "LogonType",
    "TargetUserName", "TargetUserSid", "TargetDomainName",
    "SubjectUserName", "SubjectUserSid", "SubjectDomainName",
    "ProcessName", "NewProcessName", "CommandLine", "ParentProcessName",
    "ImagePath", "ServiceName", "ServiceFileName", "TaskName",
    "SourceAddress", "SourcePort", "DestAddress", "DestPort",
    "ShareName", "ObjectName", "ObjectType", "AccessMask",
    "Status", "SubStatus", "LogonProcessName", "AuthenticationPackageName",
}


def parse_ts(ts):
    """ISO 串 → datetime(容忍 None)。"""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def main():
    mode, a = sys.argv[1], sys.argv[2]
    if mode == "ref":
        for row in ref_events(a):
            print(json.dumps(row, ensure_ascii=False))
        return
    # diff 模式(按 record_id 对齐;Go 侧截断 chunk 的 bad 记录是增量
    # 透明——PyEvtxParser 静默丢弃截断块,丰图如实补账,不算分歧)
    #
    # 对拍纪律(2026-09-21 实测两库 JSON 约定差异后拍板):
    #   必全等:record_id / channel / event_id / computer / 关键 EventData 字段
    #   ts_utc:±1ms 容忍(Velocidex float64 秒 vs PyEvtxParser ISO 文本,
    #          亚毫秒舍入路径不同,如实标注);
    #   关键字段:下方 KEY_FIELDS 清单(取证语义主干),双边存在性与归一值
    #          全等;清单外字段的结构性差异(二元 hex vs base64、
    #          Name 属性键约定、list 基数)如实计数,不算 FAIL。
    ref = [json.loads(l) for l in open(a, encoding="utf-8")]
    go = [json.loads(l) for l in open(sys.argv[3], encoding="utf-8")]
    ref_ev = {r["record_id"]: r for r in ref if r["kind"] == "event"}
    go_ev = {g["record_id"]: g for g in go if g["kind"] == "event"}
    go_bad = [g for g in go if g["kind"] != "event"]
    errors = []
    info = {"nonkey_diff": 0, "ts_within_1ms": 0}
    missing = sorted(set(ref_ev) - set(go_ev))[:5]
    extra = sorted(set(go_ev) - set(ref_ev))[:5]
    if missing:
        errors.append(f"Go 侧缺事件 record_id: {missing}")
    if extra:
        errors.append(f"Go 侧多事件 record_id: {extra}")
    for rid in sorted(ref_ev):
        if rid not in go_ev:
            continue
        r, g = ref_ev[rid], go_ev[rid]
        where = f"record_id={rid}"
        for k in ("channel", "event_id", "computer"):
            if r.get(k) != g.get(k):
                errors.append(f"{where} {k}: ref={r.get(k)!r} go={g.get(k)!r}")
        # ts:±1ms 容忍
        rt, gt = parse_ts(r.get("ts_utc")), parse_ts(g.get("ts_utc"))
        if rt is None or gt is None:
            if rt != gt:
                errors.append(f"{where} ts_utc: ref={r.get('ts_utc')} "
                              f"go={g.get('ts_utc')}")
        elif abs((rt - gt).total_seconds()) > 0.0015:
            errors.append(f"{where} ts_utc 超 ±1ms: ref={r.get('ts_utc')} "
                          f"go={g.get('ts_utc')}")
        elif rt != gt:
            info["ts_within_1ms"] += 1
        # 关键 EventData 字段:存在性 + 归一值全等
        rd, gd = norm_data(r.get("data")), norm_data(g.get("data"))
        for k in KEY_FIELDS:
            if (k in rd) != (k in gd):
                errors.append(f"{where} 关键字段 {k} 存在性: "
                              f"ref={k in rd} go={k in gd}")
            elif k in rd and rd[k] != gd[k]:
                errors.append(f"{where} 关键字段 {k}: "
                              f"ref={rd[k]!r} go={gd[k]!r}")
        # 清单外差异:如实计数
        for k in set(rd) | set(gd):
            if k not in KEY_FIELDS and rd.get(k) != gd.get(k):
                info["nonkey_diff"] += 1
        if len(errors) > 20:
            errors.append("...(错误过多,截断)")
            break
    if go_bad:
        print(f"信息: Go 侧 bad 记录 {len(go_bad)} 条(截断/坏块如实补账,"
              f"不计入对拍)")
    print(f"信息: ts ±1ms 内 {info['ts_within_1ms']} 条;"
          f"清单外字段表示差异 {info['nonkey_diff']} 处(如实)")
    if errors:
        print("FAIL")
        for e in errors:
            print(" ", e)
        sys.exit(1)
    print(f"PASS: {len(go_ev)} 条事件(record_id/channel/event_id/computer/"
          f"ts±1ms/关键 EventData 字段全等)")


if __name__ == "__main__":
    main()
