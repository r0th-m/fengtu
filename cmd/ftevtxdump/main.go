// ftevtxdump —— evtx 原生解析的 JSONL 导出(金标准对照 harness,与
// 树庭 Python 侧 tools/evtx_ref.py --events 输出逐事件对拍)。
//
// 用法: ftevtxdump <file.evtx> → stdout JSONL,每行:
//
//	{line_no, kind, record_id, channel, event_id, ts_utc, computer, data}
//
// ts_utc 为 RFC3339 毫秒(SystemTime UTC 直通);data 为平铺 EventData
// (与树庭 _flatten_eventdata 同语义;无 EventData 时兜底 UserData)。
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/ye-mengwen/fengtu/internal/ingest"
	"github.com/ye-mengwen/fengtu/internal/model"
)

type dumpRow struct {
	LineNo   int            `json:"line_no"`
	Kind     string         `json:"kind"`
	RecordID any            `json:"record_id"`
	Channel  any            `json:"channel"`
	EventID  any            `json:"event_id"`
	TsUTC    *string        `json:"ts_utc"`
	Computer any            `json:"computer"`
	Data     map[string]any `json:"data"`
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "用法: ftevtxdump <file.evtx>")
		os.Exit(2)
	}
	stream, err := ingest.VelocidexParser{}.Records(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	defer stream.Close()

	out := bytes.NewBuffer(make([]byte, 0, 1<<20))
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	n := 0
	for {
		rec, ok := stream.Next()
		if !ok {
			break
		}
		row := dumpRow{LineNo: rec.LineNo, Kind: rec.Kind}
		if rec.Kind == model.KindEvent {
			row.RecordID = rec.Norm["record_id"]
			row.Channel = rec.Norm["channel"]
			row.EventID = rec.Norm["event_id"]
			row.Computer = rec.Norm["computer"]
			if rec.TsUTCDirect != nil {
				s := model.FormatUTC(*rec.TsUTCDirect)
				row.TsUTC = &s
			}
			if d, ok := rec.Norm["data"].(map[string]any); ok {
				row.Data = d
			}
		} else if rec.Reason != nil {
			row.Data = map[string]any{"reason": *rec.Reason}
		}
		out.Reset()
		if err := enc.Encode(row); err != nil {
			fmt.Fprintf(os.Stderr, "编码失败: %v\n", err)
			os.Exit(1)
		}
		if _, err := os.Stdout.Write(out.Bytes()); err != nil {
			fmt.Fprintf(os.Stderr, "输出失败: %v\n", err)
			os.Exit(1)
		}
		n++
	}
	if err := stream.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "流错误: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "记录 %d 条(%s)\n", n, os.Args[1])
}
