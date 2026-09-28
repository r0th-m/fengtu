#!/usr/bin/env python3
"""golden 金标准生成器:以索图 Python 引擎输出为对照基准。

用法(在丰图仓根目录):
    python golden/gen_golden.py --all            # 按 MANIFEST 全量再生成
    python golden/gen_golden.py --format nginx_combined --tz Asia/Shanghai \
        --in testdata/nginx/demo-access.log --out golden/nginx.golden.jsonl
    python golden/gen_golden.py --desc testdata/desc/oa-audit-demo.yaml \
        --tz Asia/Shanghai --in ... --out ...

索图源码位置由环境变量 SUOTU_ROOT 指定(必填,指向索图仓根目录);
用 importlib 按文件路径装载 descriptor/base/normalize/nginx_combined 四个模块
(不走包 __init__,避免拉入 evtx 等重依赖)。

输出 JSONL,每行:{line_no, kind, ts_raw, ts_utc, norm, raw,
reason?, continuation_lines} —— 与 Go 侧 model.Record 的 JSON 投影同构,
Go 测试按语义(json.loads 后字典相等)对照。
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import os
import sys
import types
from datetime import timezone
from pathlib import Path

_suotu_root = os.environ.get("SUOTU_ROOT")
if not _suotu_root:
    sys.exit("SUOTU_ROOT 未设置(指向索图仓根目录,金标准对照基准)")
SUOTU_ROOT = Path(_suotu_root)
FORMATS_DIR = SUOTU_ROOT / "backend" / "app" / "formats"
APP_DIR = SUOTU_ROOT / "backend" / "app"
FENGTU_ROOT = Path(__file__).resolve().parents[1]


def _load(modname: str, path: Path, package: str):
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[modname] = mod
    spec.loader.exec_module(mod)
    return mod


def load_suotu():
    """装载索图引擎模块;descriptor.py 的相对 import 用合成包垫住。"""
    pkg = types.ModuleType("suotu_formats")
    pkg.__path__ = []
    sys.modules["suotu_formats"] = pkg
    base = _load("suotu_formats.base", FORMATS_DIR / "base.py", "suotu_formats")
    descriptor = _load("suotu_formats.descriptor",
                       FORMATS_DIR / "descriptor.py", "suotu_formats")
    nginx = _load("suotu_formats.nginx_combined",
                  FORMATS_DIR / "nginx_combined.py", "suotu_formats")
    normalize = _load("suotu_normalize", APP_DIR / "normalize.py", "")
    return base, descriptor, nginx, normalize


def iso_utc(dt) -> str | None:
    """与 Go model.FormatUTC 约定的规范形式:
    RFC3339,UTC 用 'Z',微秒非零时带 6 位小数。"""
    if dt is None:
        return None
    dt = dt.astimezone(timezone.utc)
    s = dt.strftime("%Y-%m-%dT%H:%M:%S")
    if dt.microsecond:
        s += ".%06d" % dt.microsecond
    return s + "Z"


def run(descriptor, nginx, normalize, *, format_id, desc_path, tz, in_path):
    """解析 + 归一,产出记录列表(与索图 ingest 串行路径同语义)。"""
    if format_id == "nginx_combined":
        mod = nginx
        enc = "utf-8"
    else:
        spec = descriptor.load_desc_text(Path(desc_path).read_text(encoding="utf-8"))
        mod = descriptor.CompiledDesc(spec)
        enc = mod.encoding
    records = []
    # 与 ingest._iter_lines 同:errors="replace",通用换行
    with open(in_path, "r", encoding=enc, errors="replace") as f:
        for o in mod.parse(f):
            rec = {
                "line_no": o.line_no,
                "kind": o.kind,
                "ts_raw": o.ts_raw,
                "ts_utc": iso_utc(normalize.resolve_ts_utc(o.dt_local, tz, o.ts_utc))
                if o.kind == "event" else None,
                "norm": o.norm or {},
                "raw": o.raw,
                "continuation_lines": o.continuation_lines,
            }
            if o.reason is not None:
                rec["reason"] = o.reason
            records.append(rec)
    return records


# ------------------------------------------------------------ 全量清单
# (golden 名, format_id 或 desc 路径, 输入, tz)
MANIFEST = [
    ("nginx", "nginx_combined", None,
     "testdata/nginx/demo-access.log", "Asia/Shanghai"),
    ("nginx-extra", "nginx_combined", None,
     "testdata/nginx/nginx-extra.log", "Asia/Shanghai"),
    ("oa-audit", None, "testdata/desc/oa-audit-demo.yaml",
     "testdata/desc/oa-audit.log", "Asia/Shanghai"),
    ("log4j-multiline", None, "testdata/desc/app-log4j.yaml",
     "testdata/desc/app.log4j", "UTC+8"),
    ("log4j-tight", None, "testdata/desc/app-log4j-tight.yaml",
     "testdata/desc/app.log4j-tight", "UTC+8"),
    ("json-lines", None, "testdata/desc/app-json.yaml",
     "testdata/desc/app.jsonlog", "Asia/Shanghai"),
    ("csv-lines", None, "testdata/desc/app-csv.yaml",
     "testdata/desc/app.csv", "Asia/Shanghai"),
    ("gbk-declared", None, "testdata/desc/app-gbk.yaml",
     "testdata/desc/app-gbk.log", "Asia/Shanghai"),
    ("gbk-as-utf8", None, "testdata/desc/app-utf8.yaml",
     "testdata/desc/app-gbk.log", "Asia/Shanghai"),
]


def main() -> int:
    ap = argparse.ArgumentParser(description="golden 金标准生成器(索图引擎为基准)")
    ap.add_argument("--all", action="store_true", help="按 MANIFEST 全量再生成")
    ap.add_argument("--format", dest="format_id")
    ap.add_argument("--desc", dest="desc_path")
    ap.add_argument("--tz", default=None)
    ap.add_argument("--in", dest="in_path")
    ap.add_argument("--out", dest="out_path")
    args = ap.parse_args()

    _, descriptor, nginx, normalize = load_suotu()

    jobs = []
    if args.all:
        for name, fmt, desc, inp, tz in MANIFEST:
            jobs.append((fmt, desc, tz, inp, f"golden/{name}.golden.jsonl"))
    else:
        if not args.format_id and not args.desc_path:
            ap.error("--all 或 (--format/--desc) 须给一个")
        if not args.in_path or not args.out_path:
            ap.error("单条模式须给 --in 与 --out")
        jobs.append((args.format_id, args.desc_path, args.tz,
                     args.in_path, args.out_path))

    for fmt, desc, tz, inp, outp in jobs:
        records = run(descriptor, nginx, normalize,
                      format_id=fmt, desc_path=desc, tz=tz, in_path=inp)
        out_file = FENGTU_ROOT / outp
        out_file.parent.mkdir(parents=True, exist_ok=True)
        with open(out_file, "w", encoding="utf-8", newline="\n") as f:
            for rec in records:
                f.write(json.dumps(rec, ensure_ascii=False,
                                   separators=(",", ":")) + "\n")
        n_events = sum(1 for r in records if r["kind"] == "event")
        print(f"{outp}: {len(records)} 条记录({n_events} events), tz={tz}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
