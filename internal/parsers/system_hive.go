// SYSTEM hive 复合解析器:通用键值遍历(M3 registry_hive)+ Shimcache
// 二进制专题(M3b registry_topics.go)一管双出。
//
// 为什么复合(如实记账):摄入映射表语义是「首条命中即停」,一文件一路由;
// SYSTEM 在 M3 已走 registry_hive 通用遍历(全量 registry_value 证据面,
// 金标准对拍过),M3b 新增 Shimcache 专题。若简单把 SYSTEM 改路由到
// shimcache_hive,通用遍历证据面静默回退——违反零静默纪律。故 SYSTEM
// 路由到本复合:先放通用遍历全部记录,再接 Shimcache 专题记录(行号顺接)。
// SAM/SECURITY 无此问题(通用遍历在那两个 hive 只产 F/V、Policy 不透明
// blob 的 hex,无独立证据价值,树庭同款口径:直接专题路由)。
//
// 专题打开失败(理论上通用已开成则不会)降级为 bad 记录如实记,不拖垮
// 通用面。
package parsers

import (
	"github.com/ye-mengwen/fengtu/internal/model"
)

// SystemHiveParser SYSTEM hive 复合解析器(通用遍历 + Shimcache 专题)。
type SystemHiveParser struct{}

type systemHiveStream struct {
	generic Stream
	topical Stream
	phase   int // 0=通用 1=专题 2=完
	line    int // 已放行号(专题段顺接)
}

func (SystemHiveParser) Records(path string) (Stream, error) {
	generic, err := HiveParser{}.Records(path)
	if err != nil {
		return nil, err // 非 regf/打不开:文件级如实 failed
	}
	topical, err := ShimcacheHiveParser{}.Records(path)
	if err != nil {
		// 专题失败不拖垮通用面:置空,接缝处产 bad 记录如实记
		topical = nil
		s := &systemHiveStream{generic: generic}
		reason := "Shimcache 专题打开失败(通用遍历不受影响): " + err.Error()
		s.generic = &appendBadStream{inner: generic, reason: reason}
		return s, nil
	}
	return &systemHiveStream{generic: generic, topical: topical}, nil
}

// appendBadStream 在通用流末尾追加一条 bad 记录(专题失败的如实留证)。
type appendBadStream struct {
	inner   Stream
	reason  string
	emitted bool
	last    model.Record
}

func (p *appendBadStream) Next() (model.Record, bool) {
	rec, ok := p.inner.Next()
	if ok {
		p.last = rec
		return rec, true
	}
	if !p.emitted {
		p.emitted = true
		return model.Record{LineNo: p.last.LineNo + 1, Kind: model.KindBad,
			Reason: &p.reason, Raw: "<shimcache_topic>"}, true
	}
	return model.Record{}, false
}

func (p *appendBadStream) Err() error   { return p.inner.Err() }
func (p *appendBadStream) Close() error { return p.inner.Close() }

func (s *systemHiveStream) Next() (model.Record, bool) {
	for {
		switch s.phase {
		case 0:
			rec, ok := s.generic.Next()
			if !ok {
				s.phase = 1
				continue
			}
			s.line = rec.LineNo
			return rec, true
		case 1:
			if s.topical == nil {
				s.phase = 2
				continue
			}
			rec, ok := s.topical.Next()
			if !ok {
				s.phase = 2
				continue
			}
			rec.LineNo += s.line // 行号顺接(流内 1 起,管线 BaseLineNo 恒 1)
			return rec, true
		default:
			return model.Record{}, false
		}
	}
}

func (s *systemHiveStream) Err() error {
	if err := s.generic.Err(); err != nil {
		return err
	}
	if s.topical != nil {
		return s.topical.Err()
	}
	return nil
}

func (s *systemHiveStream) Close() error {
	err := s.generic.Close()
	if s.topical != nil {
		if err2 := s.topical.Close(); err == nil {
			err = err2
		}
	}
	return err
}
