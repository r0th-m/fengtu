// netstat 快照解析器焊死:中英文表头/GBK 编码/归属回填/UDP 无状态/
// v6 括号地址/通配远端/负样本(垃圾文件零事件,结构行如实 skip)。
package parsers

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/text/encoding/simplifiedchinese"

	"github.com/ye-mengwen/fengtu/internal/model"
)

// writeNetstat 落测试样本(content 按给定编码写盘)。
func writeNetstat(t *testing.T, name, content string, gbk bool) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	var b []byte
	if gbk {
		var err error
		b, err = simplifiedchinese.GBK.NewEncoder().Bytes([]byte(content))
		if err != nil {
			t.Fatalf("GBK 编码测试样本失败: %v", err)
		}
	} else {
		b = []byte(content)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func collectRecs(t *testing.T, path string) []model.Record {
	t.Helper()
	st, err := NetstatParser{}.Records(path)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	defer st.Close()
	var out []model.Record
	for {
		rec, ok := st.Next()
		if !ok {
			break
		}
		out = append(out, rec)
	}
	if err := st.Err(); err != nil {
		t.Fatalf("流错误: %v", err)
	}
	return out
}

func eventsOf(recs []model.Record) []model.Record {
	var out []model.Record
	for _, r := range recs {
		if r.Kind == model.KindEvent {
			out = append(out, r)
		}
	}
	return out
}

// 正样本 1:英文表头 + -ano(5 段)+ 归属回填([exe] / 服务名 / 占位文案)。
func TestNetstatEnglishAno(t *testing.T) {
	path := writeNetstat(t, "netstat.txt", "\r\nActive Connections\r\n\r\n"+
		"  Proto  Local Address          Foreign Address        State           PID\r\n"+
		"  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1028\r\n"+
		"  RpcSs\r\n"+
		" [svchost.exe]\r\n"+
		"  TCP    192.168.1.10:49200     93.184.216.34:443      ESTABLISHED     4456\r\n"+
		" can not obtain ownership information\r\n"+
		"  UDP    0.0.0.0:500            *:*                                    732\r\n"+
		"  TCP    [::1]:3389             [::1]:50000            ESTABLISHED     900\r\n",
		false)
	recs := collectRecs(t, path)
	evs := eventsOf(recs)
	if len(evs) != 4 {
		t.Fatalf("事件数 = %d, want 4(recs=%v)", len(evs), recs)
	}
	// 首条:LISTENING + 归属回填([exe] 优先,服务名已在先)
	e := evs[0].Norm
	if e["proto"] != "TCP" || e["local_addr"] != "0.0.0.0" || e["local_port"] != "135" ||
		e["remote_addr"] != "0.0.0.0" || e["remote_port"] != "0" ||
		e["state"] != "LISTENING" || e["pid"] != "1028" {
		t.Fatalf("首条字段错: %v", e)
	}
	if e["service"] != "RpcSs" || e["process_name"] != "svchost.exe" {
		t.Fatalf("归属回填错: %v", e)
	}
	// 次条:ESTABLISHED,占位文案不记进程
	e = evs[1].Norm
	if e["state"] != "ESTABLISHED" || e["remote_addr"] != "93.184.216.34" ||
		e["remote_port"] != "443" || e["pid"] != "4456" {
		t.Fatalf("次条字段错: %v", e)
	}
	if _, has := e["process_name"]; has {
		t.Fatalf("占位文案不应产出 process_name: %v", e)
	}
	// UDP:无状态、远端通配 *:* → 无 remote 字段(如实)
	e = evs[2].Norm
	if e["proto"] != "UDP" || e["local_port"] != "500" || e["pid"] != "732" {
		t.Fatalf("UDP 字段错: %v", e)
	}
	if _, has := e["state"]; has {
		t.Fatalf("UDP 不应有 state: %v", e)
	}
	if _, has := e["remote_addr"]; has {
		t.Fatalf("通配 *:* 不应拆出 remote_addr: %v", e)
	}
	// v6 括号地址
	e = evs[3].Norm
	if e["local_addr"] != "::1" || e["local_port"] != "3389" ||
		e["remote_addr"] != "::1" || e["remote_port"] != "50000" {
		t.Fatalf("v6 括号地址拆分错: %v", e)
	}
	// 每行都有账(event/skip 合计 = 总行数,零静默)
	if len(recs) != 11 {
		t.Fatalf("总行账 = %d, want 11", len(recs))
	}
	// 时间戳:快照型恒 nil
	for _, r := range evs {
		if r.TsUTC != nil || r.DTLocal != nil {
			t.Fatalf("快照型不应有时间: %+v", r)
		}
	}
}

// 正样本 2:中文表头 GBK(-anob 输出实测形态)。
func TestNetstatChineseGBK(t *testing.T) {
	path := writeNetstat(t, "netstat.txt", "\r\n活动连接\r\n\r\n"+
		"  协议  本地地址          外部地址        状态           PID\r\n"+
		"  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4\r\n"+
		" 无法获取所有权信息\r\n"+
		"  TCP    192.168.1.10:445       192.168.1.20:50123     ESTABLISHED     4\r\n"+
		" [System]\r\n",
		true)
	recs := collectRecs(t, path)
	evs := eventsOf(recs)
	if len(evs) != 2 {
		t.Fatalf("事件数 = %d, want 2(recs=%v)", len(evs), recs)
	}
	e := evs[1].Norm
	if e["local_port"] != "445" || e["remote_addr"] != "192.168.1.20" ||
		e["remote_port"] != "50123" || e["state"] != "ESTABLISHED" {
		t.Fatalf("中文样本字段错: %v", e)
	}
	if e["process_name"] != "System" {
		t.Fatalf("中文归属回填错: %v", e)
	}
	// 中文占位文案不记进程到首条
	if _, has := evs[0].Norm["process_name"]; has {
		t.Fatalf("中文占位文案不应产出 process_name: %v", evs[0].Norm)
	}
}

// TCP 无 -o(4 段):state=parts[3],pid 空(与树庭字段错位的刻意偏差,
// 见 netstat.go 文件头)。
func TestNetstatTCPNoPID(t *testing.T) {
	path := writeNetstat(t, "netstat_established.txt",
		"Active Connections\n\n"+
			"  Proto  Local Address          Foreign Address        State\n"+
			"  TCP    10.0.0.5:22           10.0.0.9:60022         ESTABLISHED\n",
		false)
	evs := eventsOf(collectRecs(t, path))
	if len(evs) != 1 {
		t.Fatalf("事件数 = %d, want 1", len(evs))
	}
	e := evs[0].Norm
	if e["state"] != "ESTABLISHED" || e["local_port"] != "22" || e["remote_port"] != "60022" {
		t.Fatalf("4 段 TCP 字段错: %v", e)
	}
	if _, has := e["pid"]; has {
		t.Fatalf("无 -o 不应有 pid: %v", e)
	}
}

// 负样本:整文件垃圾 → 零事件,全部 skip 留账,不炸不猜。
func TestNetstatGarbage(t *testing.T) {
	path := writeNetstat(t, "netstat.txt", "这不是 netstat 输出\n随便一行\n\n", false)
	recs := collectRecs(t, path)
	if n := len(eventsOf(recs)); n != 0 {
		t.Fatalf("垃圾文件事件数 = %d, want 0", n)
	}
	if len(recs) != 3 {
		t.Fatalf("垃圾文件行账 = %d, want 3(全 skip)", len(recs))
	}
	for _, r := range recs {
		if r.Kind != model.KindSkip {
			t.Fatalf("垃圾行应 skip: %+v", r)
		}
	}
}

// 注册表:映射表 parser 名可解析。
func TestNetstatRegistered(t *testing.T) {
	if _, err := For("netstat"); err != nil {
		t.Fatalf("netstat 未注册: %v", err)
	}
}
