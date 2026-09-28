#!/usr/bin/env python
"""树庭面原生解析器金标准对照(M3,与 tools/evtx_golden.py 同款思路)。

参照侧口径 = 树庭 backend/app/parsers/ 的字段语义(用其同款底层库:
dissect.regf / dissect.util lzxpress_huffman;lnk/mft 按树庭 spec 注释
逐字段复刻)。Go 侧导出:ftnativedump。

用法(树庭 .venv 的 python):
  parsers_golden.py ref-pf   <file.pf>            > ref.jsonl
  parsers_golden.py ref-lnk  <file.lnk>           > ref.jsonl
  parsers_golden.py ref-hive <hive 文件> [--max N] > ref.jsonl
  parsers_golden.py ref-mft  <MFT.bin>  [--max N] > ref.jsonl(前 N 条记录)
  parsers_golden.py ref-efu  <file.efu>           > ref.jsonl(M3b)
  parsers_golden.py ref-jumplist <*.automaticDestinations-ms|*.customDestinations-ms>
                                                  > ref.jsonl(M3b,olefile)
  parsers_golden.py diff <ref.jsonl> <go.jsonl>

对拍口径:逐字段集合比对(每个对拍项声明比较键);标量按 str() 归一。
差异逐条列出,末尾汇总;退出码 0=全同,1=有差异。
"""
import json
import struct
import sys
from datetime import datetime, timezone

_FILETIME_EPOCH_DELTA = 116444736000000000


def filetime_iso(ft):
    """FILETIME → ISO UTC;非法 → None(树庭 common.filetime_to_utc 同语义)。"""
    if ft <= 0:
        return None
    try:
        return datetime.fromtimestamp(
            (ft - _FILETIME_EPOCH_DELTA) / 10_000_000, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (OverflowError, OSError, ValueError):
        return None


# ==================== Prefetch(照树庭 prefetch.py 偏移表) ====================

_PF_LAYOUTS = {17: (0x90, 0x78, 1), 23: (0x98, 0x80, 1), 26: (0xD0, 0x80, 8),
               30: (None, 0x80, 8), 31: (None, 0x80, 8)}


def ref_pf(path):
    data = open(path, "rb").read()
    compressed = False
    if data.startswith(b"MAM\x04"):
        from dissect.util.compression import lzxpress_huffman
        data = lzxpress_huffman.decompress(data[8:])
        compressed = True
    assert len(data) >= 0x54 and data[4:8] == b"SCCA", "非 SCCA"
    version = int.from_bytes(data[0:4], "little")
    run_off, times_off, n_slots = _PF_LAYOUTS[version]
    name = data[0x10:0x10 + 60].decode("utf-16-le", errors="replace")
    name = name.split("\x00")[0].strip() or None

    def u32(off):
        return int.from_bytes(data[off:off + 4], "little") \
            if off + 4 <= len(data) else 0

    if run_off is None:
        run_count = u32(0xC8) if u32(0xCC) else u32(0xD0)
    else:
        run_count = u32(run_off)
    run_times = []
    for i in range(n_slots):
        off = times_off + i * 8
        ft = int.from_bytes(data[off:off + 8], "little") \
            if off + 8 <= len(data) else 0
        iso = filetime_iso(ft)
        if iso:
            run_times.append(iso)
    out = {
        "exe_name": name, "version": version, "compressed": compressed,
        "run_count": run_count if 0 < run_count <= 10_000_000 else run_count,
        "referenced_file_count": u32(0x58),
        "prefetch_hash": f"{u32(0x4C):08X}" if u32(0x4C) else None,
        "last_run_utc": run_times[0] if run_times else None,
        "previous_runs_utc": run_times[1:],
    }
    return [out]


# ==================== LNK(照树庭 jumplist.parse_lnk) ====================

_LNK_SIG = bytes.fromhex("4c0000000114020000000000c000000000000046")


def _u16(b, o):
    return int.from_bytes(b[o:o + 2], "little")


def _u32(b, o):
    return int.from_bytes(b[o:o + 4], "little")


def ref_lnk(path):
    d = open(path, "rb").read()
    if len(d) < 0x4C or not d.startswith(_LNK_SIG):
        return [{"bad": True}]
    flags = _u32(d, 0x14)
    out = {
        "target_created": filetime_iso(int.from_bytes(d[0x1C:0x24], "little")),
        "target_modified": filetime_iso(int.from_bytes(d[0x24:0x2C], "little")),
        "target_accessed": filetime_iso(int.from_bytes(d[0x2C:0x34], "little")),
        "target": None, "arguments": None, "working_dir": None,
    }
    off = 0x4C
    if flags & 0x01:
        off += 2 + _u16(d, off)
    if flags & 0x02:
        li_size = _u32(d, off)
        li_hdr = _u32(d, off + 4)
        li_flags = _u32(d, off + 8)
        if li_flags & 0x01:
            if li_hdr >= 0x24:
                p_off = _u32(d, off + 0x1C)
                if p_off:
                    raw = d[off + p_off:off + li_size]
                    out["target"] = raw.decode(
                        "utf-16-le", errors="replace").split("\x00")[0] or None
            if out["target"] is None:
                p_off = _u32(d, off + 0x10)
                if p_off:
                    raw = d[off + p_off:off + li_size]
                    out["target"] = raw.decode(
                        "mbcs", errors="replace").split("\x00")[0] or None
        off += li_size
    unicode_str = bool(flags & 0x80)
    for bit, key in ((0x04, "name"), (0x08, "relative_path"),
                     (0x10, "working_dir"), (0x20, "arguments"),
                     (0x40, "icon_location")):
        if not flags & bit:
            continue
        if off + 2 > len(d):
            break
        count = _u16(d, off)
        off += 2
        n = count * (2 if unicode_str else 1)
        s = d[off:off + n]
        off += n
        if key in ("arguments", "working_dir"):
            out[key] = s.decode("utf-16-le" if unicode_str else "mbcs",
                                errors="replace") or None
    return [out]


# ==================== hive(dissect.regf 通用遍历,与 Go 渲染契约对齐) ====================

_REG_TYPE_NAMES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ",
                   3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN",
                   6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST",
                   9: "REG_FULL_RESOURCE_DESCRIPTOR",
                   10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD"}


def _render_hive_value(vtype, raw):
    """与 Go 侧 renderHiveValue 逐字节对齐的渲染契约。"""
    if vtype in (1, 2):
        return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
    if vtype == 7:
        text = raw.decode("utf-16-le", errors="replace")
        return [p for p in text.split("\x00") if p]
    if vtype == 4 and len(raw) == 4:
        return int.from_bytes(raw, "little")
    if vtype == 5 and len(raw) == 4:
        return int.from_bytes(raw, "big")
    if vtype == 11 and len(raw) == 8:
        return int.from_bytes(raw, "little")
    trunc = len(raw) > 512
    return {"hex": "hex:" + raw[:512].hex(), "truncated": trunc}


def ref_hive(path, max_n=0):
    from dissect.regf.regf import RegistryHive
    fh = open(path, "rb")
    hive = RegistryHive(fh)
    rows = []
    n = 0

    def walk(key, kp):
        nonlocal n
        ts = key.timestamp
        lw = ts.strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None
        for v in key.values():
            try:
                raw = v.data  # dissect: data=原始字节,value=按类型解码
                if not isinstance(raw, bytes):
                    continue
            except Exception:
                continue
            vt = v.type if isinstance(v.type, int) else v.type.value
            rendered = _render_hive_value(vt, raw)
            row = {"key_path": kp,
                   "value_name": v.name if v.name else "(Default)",
                   "value_type": _REG_TYPE_NAMES.get(vt, "REG_UNKNOWN"),
                   "key_last_write_utc": lw}
            if isinstance(rendered, dict):
                row["data"] = rendered["hex"]
                if rendered["truncated"]:
                    row["data_truncated"] = True
            else:
                row["data"] = rendered
            rows.append(row)
            n += 1
            if max_n and n >= max_n:
                return True
            if n % 200000 == 0:
                print(f"... {n}", file=sys.stderr)
        for sk in key.subkeys():
            sub = sk.name if not kp else kp + "\\" + sk.name
            if walk(sk, sub):
                return True
        return False

    walk(hive.root(), "")
    fh.close()
    return rows


# ==================== MFT(树庭 mft.py 同 spec,纯 struct 复刻) ====================

_NS_PRIORITY = {3: 0, 1: 1, 0: 2, 2: 3}


def _mft_scan(buf):
    """一条记录 → dict 或 None(坏记录)。照树庭 _walk_attrs/_parse_fn。"""
    if buf[:4] != b"FILE":
        return None
    usa_ofs, usa_cnt = struct.unpack_from("<HH", buf, 4)
    if usa_cnt == 0 or usa_ofs + 2 * usa_cnt > 1024:
        return None
    buf = bytearray(buf)
    for i in range(1, usa_cnt):
        end = i * 512
        if end > 1024:
            break
        if buf[end - 2] != buf[usa_ofs] or buf[end - 1] != buf[usa_ofs + 1]:
            return None
        buf[end - 2:end] = buf[usa_ofs + 2 * i:usa_ofs + 2 * i + 2]
    flags = struct.unpack_from("<H", buf, 22)[0]
    attr_off = struct.unpack_from("<H", buf, 20)[0]
    si = (0, 0, 0, 0)
    best = None
    non_dos = 0
    off = attr_off
    while off + 16 <= len(buf):
        atype, alen = struct.unpack_from("<II", buf, off)
        if atype == 0xFFFFFFFF or alen == 0 or off + alen > len(buf):
            break
        if atype in (0x10, 0x30) and buf[off + 8] == 0:
            vlen, voff = struct.unpack_from("<IH", buf, off + 16)
            val = buf[off + voff:off + voff + vlen]
            if atype == 0x10 and len(val) >= 32:
                si = struct.unpack_from("<QQQQ", val, 0)
            elif atype == 0x30 and len(val) >= 66:
                parent = struct.unpack_from("<Q", val, 0)[0] & 0xFFFFFFFFFFFF
                nlen, ns = val[64], val[65]
                if 66 + nlen * 2 <= len(val):
                    name = val[66:66 + nlen * 2].decode(
                        "utf-16-le", errors="replace")
                    if ns in (0, 1, 3):
                        non_dos += 1
                    pri = _NS_PRIORITY.get(ns, 9)
                    if best is None or pri < best[0]:
                        best = (pri, parent, name,
                                struct.unpack_from("<Q", val, 8)[0],
                                struct.unpack_from("<Q", val, 16)[0],
                                struct.unpack_from("<Q", val, 48)[0], ns)
        off += alen
    out = {"flags": flags, "si": si, "fn": best[1:] if best else None,
           "non_dos": non_dos}
    return out


def ref_mft(path, max_n=0):
    """前 max_n 条记录(0=全量)的逐条字段(不含路径——路径拼接是两边各自
    实现,对拍放 name/parent/timestamps/flags/size;路径正确性由合成测试
    焊死,真实件抽查)。"""
    import os
    size = os.path.getsize(path)
    total = size // 1024
    if max_n:
        total = min(total, max_n)
    rows = []
    with open(path, "rb") as f:
        for seg in range(total):
            buf = f.read(1024)
            if len(buf) < 1024:
                break
            sc = _mft_scan(buf)
            if sc is None or sc["fn"] is None:
                continue
            parent, name, fc, fm, fsize, ns = sc["fn"]
            rows.append({
                "record_number": seg, "name": name, "parent_record": parent,
                "is_dir": bool(sc["flags"] & 0x2),
                "in_use": bool(sc["flags"] & 0x1),
                "size": None if sc["flags"] & 0x2 else fsize,
                "si_created_utc": filetime_iso(sc["si"][0]),
                "si_modified_utc": filetime_iso(sc["si"][1]),
                "fn_created_utc": filetime_iso(fc),
                "fn_modified_utc": filetime_iso(fm),
                "fn_namespace": ns,
            })
            if len(rows) % 200000 == 0:
                print(f"... {len(rows)} (seg {seg})", file=sys.stderr)
    return rows


# ==================== EFU(树庭 efu.py 同契约,M3b) ====================


def ref_efu(path):
    """EFU 行级字段(与 Go file_listing_entry 对拍;summary 计数单独核对)。"""
    import csv
    rows = []
    with open(path, "r", encoding="utf-8-sig", newline="",
              errors="replace") as f:
        reader = csv.reader(f)
        header = None
        idx = {}
        for cells in reader:
            if header is None:
                if not cells or all(not c.strip() for c in cells):
                    continue
                header = [c.strip().lower() for c in cells]
                assert "filename" in header, f"无法识别 EFU 表头: {header[:5]}"
                idx = {n: header.index(n) for n in
                       ("filename", "size", "date modified", "date created")
                       if n in header}
                continue
            if not cells:
                continue
            name = cells[idx["filename"]] if len(cells) > idx["filename"] else ""
            if not name:
                continue

            def cell(col):
                i = idx.get(col)
                if i is None or i >= len(cells):
                    return None
                v = cells[i].strip()
                return v or None

            base = name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
            ext = None
            if "." in base:
                ext = base.rsplit(".", 1)[-1].lower() or None
            if not base:
                base, ext = name, None
            row = {"path": name, "filename": base}
            if ext:
                row["extension"] = ext
            sv = cell("size")
            if sv:
                try:
                    row["size_bytes"] = int(sv)
                except ValueError:
                    pass
            for col, key in (("date modified", "date_modified_utc"),
                             ("date created", "date_created_utc")):
                v = cell(col)
                if v:
                    try:
                        iso = filetime_iso(int(v))
                    except ValueError:
                        iso = None
                    if iso:
                        row[key] = iso
            rows.append(row)
    return rows


# ==================== JumpList(树庭 jumplist.py 同契约,M3b) ====================


def ref_jumplist(path):
    """JumpList 条目(与 Go jumplist_entry 对拍;顺序 = destlist 条目 +
    LNK 流,与 Go 侧 emit 序对齐)。"""
    import olefile
    import os
    rows = []
    app_id = os.path.basename(path).lower().split(".")[0]
    if path.lower().endswith(".automaticdestinations-ms"):
        ole = olefile.OleFileIO(path)
        try:
            names = ["/".join(n) for n in
                     ole.listdir(streams=True, storages=False)]
            if ole.exists("DestList"):
                d = ole.openstream("DestList").read()
                if len(d) >= 0x20:
                    n = _u32(d, 4)
                    off = 0x20
                    for _i in range(n):
                        if off + 0x84 > len(d):
                            break
                        entry_no = _u32(d, off + 0x58)
                        ft = int.from_bytes(d[off + 0x64:off + 0x6C], "little")
                        sl = _u16(d, off + 0x80)
                        s_end = off + 0x82 + sl * 2
                        if s_end + 4 > len(d):
                            break
                        target = d[off + 0x82:s_end].decode(
                            "utf-16-le", errors="replace")
                        row = {"app_id": app_id, "source": "destlist",
                               "entry_no": entry_no, "target_path": target}
                        iso = filetime_iso(ft)
                        if iso:
                            row["accessed_utc"] = iso
                        rows.append(row)
                        trailer = _u32(d, s_end)
                        off = s_end + trailer + 4
            for name in names:
                leaf = name.rsplit("/", 1)[-1]
                if not leaf.isdigit():
                    continue
                blob = ole.openstream(name).read()
                try:
                    lnk = ref_lnk_blob(blob)
                except ValueError:
                    continue
                row = {"app_id": app_id, "source": "lnk_stream",
                       "entry_no": int(leaf)}
                _jl_lnk_fields(row, lnk)
                rows.append(row)
        finally:
            ole.close()
    else:  # customDestinations
        data = open(path, "rb").read()
        offs = []
        i = data.find(_LNK_SIG)
        while i != -1:
            offs.append(i)
            i = data.find(_LNK_SIG, i + 1)
        for idx, off in enumerate(offs):
            end = offs[idx + 1] - 20 if idx + 1 < len(offs) else len(data)
            try:
                lnk = ref_lnk_blob(data[off:end])
            except ValueError:
                continue
            row = {"app_id": app_id, "source": "custom_lnk"}
            _jl_lnk_fields(row, lnk)
            rows.append(row)
    return rows


def ref_lnk_blob(d):
    """ref_lnk 的 blob 版(抛 ValueError)。"""
    if len(d) < 0x4C or not d.startswith(_LNK_SIG):
        raise ValueError("非 LNK")
    import tempfile, os
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(d)
        tmp = f.name
    try:
        return ref_lnk(tmp)[0]
    finally:
        os.unlink(tmp)


def _jl_lnk_fields(row, lnk):
    if lnk.get("target"):
        row["target_path"] = lnk["target"]
    if lnk.get("arguments"):
        row["arguments"] = lnk["arguments"]
    for k_src, k_dst in (("target_accessed", "accessed_utc"),
                         ("target_created", "created_utc"),
                         ("target_modified", "modified_utc")):
        if lnk.get(k_src):
            row[k_dst] = lnk[k_src]


# ==================== diff ====================

def _norm(v):
    """标量归一(Go float64 vs Python int 等表示差异)。"""
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if isinstance(v, list):
        return [_norm(x) for x in v]
    return str(v) if not isinstance(v, (dict, list)) else v


def diff(ref_path, go_path):
    """逐字段对照:ref 定义契约键集;Go 行的 norm 为字段载体(ftnativedump
    输出 {line_no,kind,ts_utc,norm})。Go 多出契约外的字段(如 volume_paths)
    如实列出但不判负(补充字段,见 parsers 文件头)。"""
    ref = [json.loads(x) for x in open(ref_path, encoding="utf-8")]
    go_raw = [json.loads(x) for x in open(go_path, encoding="utf-8")]
    go = []
    go_bad = 0
    for r in go_raw:
        if r.get("kind") == "bad":
            go_bad += 1  # bad 行不参与逐条对照,单独如实计数
            continue
        norm = r.get("norm", r)
        et = norm.get("event_type", "") if isinstance(norm, dict) else ""
        if str(et).endswith("_summary"):
            continue  # Go 侧收尾汇总事件不参与逐条对照(计数单独核对)
        go.append(norm)
    if go_bad:
        print(f"Go 侧 bad 记录 {go_bad} 条(不参与逐条对照,原因在 norm.reason)")
    print(f"ref {len(ref)} 条,go {len(go)} 条")
    # hive 等无序遍历格式:两侧按 (key_path, value_name) 排序再对拍
    # (遍历序是库实现细节,不是语义;集合+字段值才是)
    if ref and isinstance(ref[0], dict) and "key_path" in ref[0]:
        ref.sort(key=lambda r: (str(r.get("key_path")), str(r.get("value_name"))))
        go.sort(key=lambda r: (str(r.get("key_path")), str(r.get("value_name"))))
    # MFT:按 record_number 排序(Go 侧 timestomp 候选先行,行序不同构)
    if ref and isinstance(ref[0], dict) and "record_number" in ref[0]:
        go = [r for r in go if r.get("event_type") in (None, "mft_entry")]
        ref.sort(key=lambda r: r.get("record_number"))
        go.sort(key=lambda r: r.get("record_number"))
    if len(ref) != len(go):
        print(f"!! 条数不符: ref={len(ref)} go={len(go)}")
    extras_reported = set()
    bad = 0
    for i, (a, b) in enumerate(zip(ref, go)):
        delta = {}
        for k in sorted(a):
            va, vb = _norm(a.get(k)), _norm(b.get(k))
            if va != vb:
                delta[k] = (a.get(k), b.get(k))
        for k in sorted(set(b) - set(a) - {"event_type"}):
            if k not in extras_reported:
                extras_reported.add(k)
        if delta:
            bad += 1
            if bad <= 10:
                print(f"差异 #{i}: {delta}")
    if extras_reported:
        print(f"Go 契约外补充字段(不判负): {sorted(extras_reported)}")
    print(f"对拍完成: {min(len(ref), len(go))} 条逐字段比对,{bad} 条有差异")
    return 1 if bad or len(ref) != len(go) else 0


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")  # Windows 中文控制台默认 GBK
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    if cmd == "diff":
        return diff(sys.argv[2], sys.argv[3])
    max_n = 0
    if "--max" in sys.argv:
        i = sys.argv.index("--max")
        max_n = int(sys.argv[i + 1])
    if cmd == "ref-pf":
        rows = ref_pf(sys.argv[2])
    elif cmd == "ref-lnk":
        rows = ref_lnk(sys.argv[2])
    elif cmd == "ref-hive":
        rows = ref_hive(sys.argv[2], max_n)
    elif cmd == "ref-mft":
        rows = ref_mft(sys.argv[2], max_n)
    elif cmd == "ref-efu":
        rows = ref_efu(sys.argv[2])
    elif cmd == "ref-jumplist":
        rows = ref_jumplist(sys.argv[2])
    else:
        print(__doc__)
        return 2
    for r in rows:
        sys.stdout.write(json.dumps(r, ensure_ascii=False) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
