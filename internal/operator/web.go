// Web 日志族算子(键=src_ip;状态码语义/阈值全走 YAML params)。
//
// 判定要点(§6.1 第三层,随命中 detail 返回,真案换来的噪音区分智慧):
//   - 爆破链:先确认应用的成功语义(哪些状态码算「登录成功」是应用属性,
//     params 可配,默认 401/403→200 只是通用起点);
//   - 周期信标:先查 IP 归属(CDN/监控/负载均衡探活会产生完美周期);
//   - 速率突刺:先排除发布/活动等业务高峰,确认该 IP 是单一终端而非
//     NAT 出口。
package operator

import (
	"math"
	"time"

	"github.com/ye-mengwen/fengtu/internal/query"
)

// ---- sequence:爆破链(失败×N → 窗口内成功) ----

type bruteForceChain struct{}

type bfParams struct {
	failThreshold int
	windowSeconds int
	windowLines   int
	failStatus    map[string]bool
	successStatus map[string]bool
}

func (bruteForceChain) params(spec *Spec) (bfParams, error) {
	thr, err := intParam(spec, "fail_threshold", 10)
	if err != nil {
		return bfParams{}, err
	}
	ws, err := intParam(spec, "window_seconds", 600)
	if err != nil {
		return bfParams{}, err
	}
	wl, err := intParam(spec, "window_lines", 2000)
	if err != nil {
		return bfParams{}, err
	}
	fails, err := strListParam(spec, "fail_status", []string{"401", "403"})
	if err != nil {
		return bfParams{}, err
	}
	success, err := strListParam(spec, "success_status", []string{"200"})
	if err != nil {
		return bfParams{}, err
	}
	if thr < 2 {
		thr = 2
	}
	return bfParams{thr, ws, wl, strSet(fails), strSet(success)}, nil
}

type bfState struct {
	fails       int
	anchorLine  int        // 第 N 次失败行号(窗口起点)
	anchorTS    *time.Time // 第 N 次失败时刻(ts 可用时窗口按秒)
	anchorFirst int        // 首次失败行号(detail 留证)
}

func (bruteForceChain) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	p, err := bruteForceChain{}.params(spec)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, src := range srcs {
		states := map[string]*bfState{}
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			ip := fieldStr(f, "src_ip")
			if ip == "" {
				return nil
			}
			status := fieldStr(f, "status")
			st := states[ip]
			if st == nil {
				st = &bfState{}
				states[ip] = st
			}
			switch {
			case p.failStatus[status]:
				st.fails++
				if st.fails == 1 {
					st.anchorFirst = ev.LineNo
				}
				if st.fails == p.failThreshold {
					st.anchorLine = ev.LineNo
					st.anchorTS = ev.TS
				}
			case p.successStatus[status]:
				if st.fails >= p.failThreshold && st.anchorLine > 0 &&
					ev.LineNo > st.anchorLine && withinWindow(ev, st, p) {
					basis, actual := windowDetail(ev, st)
					out = append(out, Finding{
						SourceID: src.ID, LineNo: ev.LineNo, TS: ev.TS,
						MatchedField: "src_ip", MatchedValue: ip,
						Snippet: ev.Raw,
						Detail: map[string]any{
							"src_ip": ip, "fail_count": st.fails,
							"fail_first_line": st.anchorFirst,
							"fail_nth_line":   st.anchorLine,
							"success_line":    ev.LineNo,
							"window_basis":    basis, "window_actual": actual,
							"judgement_hint": "先确认应用的成功语义(哪些状态码算登录成功是应用属性,params 可配)",
						},
						Evidence: Evidence{IndependentPoints: 2, ChainLinked: true},
					})
					delete(states, ip) // 一段爆破一次账,防刷屏
				}
			}
			return nil
		})
		if serr != nil {
			return out, serr
		}
	}
	return out, nil
}

// withinWindow 窗口判定:ts 可用按秒;无时区源(ts nil)降级按行距,
// 如实记 window_basis(不猜时区是硬纪律,窗口语义降级如实标)。
func withinWindow(ev query.Event, st *bfState, p bfParams) bool {
	if ev.TS != nil && st.anchorTS != nil {
		return secondsBetween(*ev.TS, *st.anchorTS) <= float64(p.windowSeconds)
	}
	return ev.LineNo-st.anchorLine <= p.windowLines
}

func windowDetail(ev query.Event, st *bfState) (string, float64) {
	if ev.TS != nil && st.anchorTS != nil {
		return "seconds", secondsBetween(*ev.TS, *st.anchorTS)
	}
	return "lines", float64(ev.LineNo - st.anchorLine)
}

// ---- periodicity:周期信标(cv + 样本数 + 跨度三闸) ----

type beaconPeriodicity struct{}

type beaconState struct {
	samples   int
	firstTS   time.Time
	lastTS    time.Time
	firstLine int
	lastLine  int
	lastTSok  bool
	noTS      int
	// Welford 在线均值/方差(间隔秒)
	n    int
	mean float64
	m2   float64
}

func (beaconPeriodicity) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	minSamples, err := intParam(spec, "min_samples", 12)
	if err != nil {
		return nil, err
	}
	minSpan, err := intParam(spec, "min_span_seconds", 3600)
	if err != nil {
		return nil, err
	}
	maxCV, err := floatParam(spec, "max_cv", 0.15)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, src := range srcs {
		states := map[string]*beaconState{}
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			ip := fieldStr(f, "src_ip")
			if ip == "" {
				return nil
			}
			st := states[ip]
			if st == nil {
				st = &beaconState{}
				states[ip] = st
			}
			if ev.TS == nil {
				st.noTS++
				return nil
			}
			st.samples++
			if st.samples == 1 {
				st.firstTS, st.firstLine = *ev.TS, ev.LineNo
			} else if st.lastTSok {
				if iv := ev.TS.Sub(st.lastTS).Seconds(); iv > 0 {
					st.n++
					delta := iv - st.mean
					st.mean += delta / float64(st.n)
					st.m2 += delta * (iv - st.mean)
				}
			}
			st.lastTS, st.lastLine, st.lastTSok = *ev.TS, ev.LineNo, true
			return nil
		})
		if serr != nil {
			return out, serr
		}
		for ip, st := range states {
			span := st.lastTS.Sub(st.firstTS).Seconds()
			if st.samples < minSamples || st.n < 2 || span < float64(minSpan) {
				continue
			}
			std := math.Sqrt(st.m2 / float64(st.n))
			cv := 0.0
			if st.mean > 0 {
				cv = std / st.mean
			}
			if cv > maxCV {
				continue
			}
			out = append(out, Finding{
				SourceID: src.ID, LineNo: st.lastLine, TS: &st.lastTS,
				MatchedField: "src_ip", MatchedValue: ip,
				Detail: map[string]any{
					"src_ip": ip, "samples": st.samples, "intervals": st.n,
					"span_seconds": span, "mean_interval_s": st.mean,
					"stddev_interval_s": std, "cv": cv,
					"events_without_ts": st.noTS,
					"judgement_hint":    "先查 IP 归属——CDN/监控/负载均衡探活会产生完美周期",
				},
				Evidence: Evidence{StatisticalOnly: true, Exclusions: []string{
					"排除 CDN/监控/负载均衡探活等自动化来源(查 IP 归属)",
					"对照业务基线确认该周期不是正常轮询",
				}},
			})
		}
	}
	return out, nil
}

// ---- ip-rate-spike:单 IP 请求速率突刺(分桶基线 + z 闸) ----

type ipRateSpike struct{}

type spikeState struct {
	buckets     map[int64]int
	bucketFirst map[int64]int
	bucketTS    map[int64]time.Time
	noTS        int
}

func (ipRateSpike) Run(spec *Spec, srcs []Source, stream StreamFunc) ([]Finding, error) {
	bucketSec, err := intParam(spec, "bucket_seconds", 60)
	if err != nil {
		return nil, err
	}
	minBuckets, err := intParam(spec, "min_buckets", 10)
	if err != nil {
		return nil, err
	}
	zThr, err := floatParam(spec, "z_threshold", 5.0)
	if err != nil {
		return nil, err
	}
	minCount, err := intParam(spec, "min_bucket_count", 100)
	if err != nil {
		return nil, err
	}
	var out []Finding
	for _, src := range srcs {
		states := map[string]*spikeState{}
		serr := stream(src.ID, func(ev query.Event) error {
			f := fieldsOf(ev.Fields)
			ip := fieldStr(f, "src_ip")
			if ip == "" {
				return nil
			}
			if ev.TS == nil {
				st := states[ip]
				if st == nil {
					st = &spikeState{}
					states[ip] = st
				}
				st.noTS++
				return nil
			}
			st := states[ip]
			if st == nil {
				st = &spikeState{buckets: map[int64]int{},
					bucketFirst: map[int64]int{}, bucketTS: map[int64]time.Time{}}
				states[ip] = st
			}
			b := ev.TS.Unix() / int64(bucketSec)
			if st.buckets[b] == 0 {
				st.bucketFirst[b] = ev.LineNo
				st.bucketTS[b] = ev.TS.UTC()
			}
			st.buckets[b]++
			return nil
		})
		if serr != nil {
			return out, serr
		}
		for ip, st := range states {
			if len(st.buckets) < minBuckets {
				continue
			}
			var sum, sumSq float64
			for _, c := range st.buckets {
				sum += float64(c)
				sumSq += float64(c) * float64(c)
			}
			n := float64(len(st.buckets))
			mean := sum / n
			std := math.Sqrt(sumSq/n - mean*mean)
			// 每个 IP 只报 z 最高的一桶(防刷屏;detail 直给全量基线)
			var topB int64
			topZ := 0.0
			for b, c := range st.buckets {
				if c < minCount || std == 0 {
					continue
				}
				if z := (float64(c) - mean) / std; z > zThr && z > topZ {
					topZ, topB = z, b
				}
			}
			if topZ == 0 {
				continue
			}
			ts := st.bucketTS[topB]
			out = append(out, Finding{
				SourceID: src.ID, LineNo: st.bucketFirst[topB], TS: &ts,
				MatchedField: "src_ip", MatchedValue: ip,
				Detail: map[string]any{
					"src_ip": ip, "bucket_start": ts.Format(time.RFC3339),
					"bucket_seconds": bucketSec, "bucket_count": st.buckets[topB],
					"buckets": len(st.buckets), "mean_per_bucket": mean,
					"stddev_per_bucket": std, "z": topZ,
					"events_without_ts": st.noTS,
					"judgement_hint":    "先排除发布/活动等业务高峰;确认该 IP 是单一终端而非 NAT 出口",
				},
				Evidence: Evidence{StatisticalOnly: true, Exclusions: []string{
					"排除发布/活动/备份窗口等业务高峰",
					"确认该 IP 为单一终端而非 NAT/代理出口(出口聚合天然高量)",
				}},
			})
		}
	}
	return out, nil
}
