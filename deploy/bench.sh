#!/usr/bin/env bash
# 丰图 v2 性能军令状台架(DESIGN §4.3)。在台架 VM 上执行:
#   /opt/fengtu/deploy/bench.sh          # 全流程(摄入 + 扫描)
#   /opt/fengtu/deploy/bench.sh clean    # 清空 bench 数据重来
#
# 验收基线(§4.3):
#   894MB nginx ≤ 20s | 5.8GB catalina ≤ 90s | 3000 万行典型扫描 ≤ 60s
#
# 语料实情(如实标注):
#   - big_access.log 实为 1.24GB / 10,000,020 行(非 894MB)。SLO 判定用
#     894MiB 头部切样(任务书口径),全量摄入数字并列实测;
#   - catalina.out 实为 6.1GB;
#   - 3000 万行扫描语料 = big_access.log ×3 拼接(SLO 语料规格,
#     生成/摄入耗时如实记录,不在 SLO 判定内)。
# 实测数字打印并写入 /opt/fengtu/bench/bench-result.txt(账本凭证)。
set -uo pipefail

FT=/opt/fengtu/bin/ftingest
BENCH=/opt/fengtu/bench
DESC=/opt/fengtu/configs/desc/tomcat-catalina.yaml
RES=$BENCH/bench-result.txt

BENCH_HOST=${FENGTU_BENCH_HOST:-127.0.0.1}
BENCH_PASS=${FENGTU_BENCH_PASS:?FENGTU_BENCH_PASS 未配(台架口令,先 export 再跑)}
export FENGTU_CH=$BENCH_HOST:9000
export FENGTU_CH_USER=fengtu
export FENGTU_CH_PASS=$BENCH_PASS
export FENGTU_PG=postgres://fengtu:$BENCH_PASS@$BENCH_HOST:5432/fengtu
# 台架实测最优摄入姿态(2026-09-21 调参扫描,全量 1.24GB 五组对照):
# workers=3(留一核给聚合/插入/读取,比 4 worker 快 ~15%,5 worker 崩)、
# GOGC=200(摄入分配率高,降 GC 频率)、ch-compress=none(内网带宽充足,
# 省插入侧压缩 CPU)。台架 4 核语境;换机型须重扫。
export GOGC=200
export FENGTU_CH_COMPRESS=none
WORKERS=3

chq() { docker exec fengtu-clickhouse clickhouse-client \
  --user fengtu --password "$FENGTU_CH_PASS" -q "$1"; }
pgq() { docker exec fengtu-postgres psql -U fengtu -tAc "$1"; }
rows_of() { chq "SELECT count() FROM fengtu.events WHERE case_id='$1'"; }

if [ "${1:-}" = "clean" ]; then
  chq "TRUNCATE TABLE fengtu.events"
  pgq "TRUNCATE cases CASCADE"
  echo "已清空 fengtu.events 与 cases 级联"
  exit 0
fi

echo "== 丰图 v2 军令状台架 $(date -Is) ==" | tee "$RES"
echo "主机: $(nproc) 核 / $(free -g | awk 'NR==2{print $2}')GB" | tee -a "$RES"

# CPU 采样(落文件;ps %cpu 口径,100%=单核跑满,本机上限 400%)
cpu_sampler() { # $1=pid $2=采样文件
  local v
  : > "$2"
  while kill -0 "$1" 2>/dev/null; do
    v=$(ps -o %cpu= -p "$1" 2>/dev/null || echo 0)
    echo "$v" >> "$2"
    sleep 1
  done
}
cpu_avg() { awk '{s+=$1; n++} END{if(n>0) printf "%.0f", s/n; else print "NA"}' "$1"; }

ingest_timed() { # $1=标签 $2=子命令 $3..=子命令参数
  local label=$1 sub=$2; shift 2
  "$FT" "$sub" --workers "$WORKERS" "$@" > "$BENCH/$label.ingest.log" 2>&1 &
  local pid=$!
  cpu_sampler $pid "$BENCH/$label.cpu" &
  local t0=$(date +%s.%N)
  wait $pid; local rc=$?
  local t1=$(date +%s.%N)
  echo "$label 摄入耗时: $(echo "$t1 - $t0" | bc)s cpu均值: $(cpu_avg "$BENCH/$label.cpu")% rc=$rc" | tee -a "$RES"
  cat "$BENCH/$label.ingest.log" | tee -a "$RES"
  return $rc
}

# ---- 0) 894MiB 头部切样(任务书 SLO 口径) ----
if [ ! -f "$BENCH/big_access_894m.log" ]; then
  head -c 937426944 "$BENCH/big_access.log" > "$BENCH/big_access_894m.log"
fi

# ---- 1) nginx 894MB ≤ 20s(SLO 判定) + 全量 1.24GB(旁证) ----
ingest_timed nginx894 text --case bench-nginx-894 --format nginx_combined \
  --tz Asia/Shanghai "$BENCH/big_access_894m.log" || exit 1
NGINX894_S=$(grep -oP 'nginx894 摄入耗时: \K[\d.]+' "$RES")

ingest_timed nginxfull text --case bench-nginx-full --format nginx_combined \
  --tz Asia/Shanghai "$BENCH/big_access.log" || exit 1
NGINXFULL_S=$(grep -oP 'nginxfull 摄入耗时: \K[\d.]+' "$RES")

# ---- 2) catalina 5.8GB ≤ 90s ----
ingest_timed catalina text --case bench-catalina --desc "$DESC" \
  --tz Asia/Shanghai "$BENCH/catalina.out" || exit 1
CATA_S=$(grep -oP 'catalina 摄入耗时: \K[\d.]+' "$RES")

# ---- 3) 3000 万行扫描语料(3x 拼接,生成/摄入如实记录) ----
if [ ! -f "$BENCH/big_access_3x.log" ]; then
  echo "-- 生成 3x 语料" | tee -a "$RES"
  cat "$BENCH/big_access.log" "$BENCH/big_access.log" \
      "$BENCH/big_access.log" > "$BENCH/big_access_3x.log"
fi
ingest_timed scan30m text --case bench-scan --format nginx_combined \
  --tz Asia/Shanghai "$BENCH/big_access_3x.log" || exit 1
SCAN_S=$(grep -oP 'scan30m 摄入耗时: \K[\d.]+' "$RES")

NGINX_CID=$(pgq "SELECT id FROM cases WHERE name='bench-nginx-full'")
CATA_CID=$(pgq "SELECT id FROM cases WHERE name='bench-catalina'")
SCAN_CID=$(pgq "SELECT id FROM cases WHERE name='bench-scan'")
echo "行数: nginx894=$(rows_of $(pgq "SELECT id FROM cases WHERE name='bench-nginx-894'")) nginx全量=$(rows_of $NGINX_CID) catalina=$(rows_of $CATA_CID) scan30m=$(rows_of $SCAN_CID) 全表=$(chq 'SELECT count() FROM fengtu.events')" | tee -a "$RES"

# ---- 4) 典型扫描查询(3000 万行 case,--time 实测) ----
SCAN_SECS=()
run_scan() { # $1=名称 $2=SQL
  local out secs
  out=$(docker exec fengtu-clickhouse clickhouse-client --user fengtu \
    --password "$FENGTU_CH_PASS" --time -q "$2" 2>&1)
  secs=$(echo "$out" | tail -1)
  echo "$out" | head -6 | sed 's/^/    /' >> "$RES"
  echo "扫描[$1]: ${secs}s" | tee -a "$RES"
  SCAN_SECS+=("$secs")
}
run_scan "按天聚合" \
  "SELECT toDate(ts) d, count() FROM fengtu.events WHERE case_id='$SCAN_CID' GROUP BY d ORDER BY d"
run_scan "状态码分布" \
  "SELECT JSONExtractUInt(fields,'status') s, count() c FROM fengtu.events WHERE case_id='$SCAN_CID' AND kind='event' GROUP BY s ORDER BY c DESC"
run_scan "Top IP" \
  "SELECT JSONExtractString(fields,'src_ip') ip, count() c FROM fengtu.events WHERE case_id='$SCAN_CID' AND kind='event' GROUP BY ip ORDER BY c DESC LIMIT 20"

judge() { awk -v n="$1" -v a="$2" -v l="$3" 'BEGIN{
  if (a+0 <= l+0) printf "PASS %s: %.1fs ≤ %.0fs\n", n, a, l;
  else printf "FAIL %s: %.1fs > %.0fs\n", n, a, l}'; }
{
  echo "== SLO 判定(DESIGN §4.3) =="
  judge "nginx 894MB 摄入" "$NGINX894_S" 20
  judge "catalina 5.8GB 摄入" "$CATA_S" 90
  judge "3000万行扫描·按天聚合" "${SCAN_SECS[0]}" 60
  judge "3000万行扫描·状态码分布" "${SCAN_SECS[1]}" 60
  judge "3000万行扫描·Top IP" "${SCAN_SECS[2]}" 60
  echo "旁证: nginx 全量 1.24GB 摄入 ${NGINXFULL_S}s;30M 语料摄入 ${SCAN_S}s"
  echo "CPU 均值: nginx894=$(cpu_avg $BENCH/nginx894.cpu)% catalina=$(cpu_avg $BENCH/catalina.cpu)% scan30m=$(cpu_avg $BENCH/scan30m.cpu)%(400=4 核跑满)"
} | tee -a "$RES"
