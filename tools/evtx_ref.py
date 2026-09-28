#!/usr/bin/env python
"""evtx 摄入对照基准(金标准思路,同切片一):
树庭 Python 侧用什么解析 evtx,这里就用什么产出参照账——
PyPI `evtx`(PyEvtxParser,与 evtx_dump 同一 Rust 解析核心)。

对账口径(照 backend/app/parsers/evtx_log.py 的账目语义):
  total_records   解析器产出的记录总数
  imported        有效记录(EventID 能转出 int)
  bad_records     逐条失败/非法计数(零静默)
  first_record_utc / last_record_utc   记录时间戳(min/max)
  channel_event_counts   "channel|event_id" 聚合计数(抽样对账)

用法: evtx_ref.py <file.evtx> [file2.evtx ...]  → stdout JSON(逐文件)
"""
import json
import sys

from evtx import PyEvtxParser


def account(path: str) -> dict:
    parser = PyEvtxParser(path)
    total = imported = bad = 0
    first_ts = last_ts = None
    agg: dict[str, int] = {}
    for rec in parser.records_json():
        total += 1
        try:
            record_id = int(rec.get("event_record_id") or total)
            ev = json.loads(rec["data"])
            system = ev.get("Event", {}).get("System", {})
        except (TypeError, ValueError, AttributeError, json.JSONDecodeError):
            bad += 1
            continue
        v = system.get("EventID")
        if isinstance(v, dict):
            v = v.get("#text")
        try:
            event_id = int(v)
        except (TypeError, ValueError):
            bad += 1
            continue
        channel = str(system.get("Channel") or "")
        agg[f"{channel}|{event_id}"] = agg.get(f"{channel}|{event_id}", 0) + 1
        ts = rec.get("timestamp")
        if isinstance(ts, str):
            first_ts = ts if first_ts is None or ts < first_ts else first_ts
            last_ts = ts if last_ts is None or ts > last_ts else last_ts
        imported += 1
        _ = record_id
    return {
        "file": path,
        "total_records": total,
        "imported_records": imported,
        "bad_records": bad,
        "first_record_utc": first_ts,
        "last_record_utc": last_ts,
        "channel_event_counts": dict(
            sorted(agg.items(), key=lambda kv: -kv[1])),
    }


def main() -> None:
    out = [account(p) for p in sys.argv[1:]]
    json.dump(out, sys.stdout, ensure_ascii=False, indent=1)
    print()


if __name__ == "__main__":
    main()
