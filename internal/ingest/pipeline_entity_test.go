// 实体抽取管线焊死(0.25.0-datasource-unlock):MetaStore 实现 EntitySink
// 时,摄入事件的同时抽实体落实体表(键级去重、锚点保首见、主机键随行);
// 未实现 EntitySink 的存储不抽(向后兼容)。
package ingest

import (
	"context"
	"sync"
	"testing"

	"github.com/ye-mengwen/fengtu/internal/descform"

	"github.com/ye-mengwen/fengtu/internal/entity"
)

// fakeMetaWithEntities fakeMeta + EntitySink。
type fakeMetaWithEntities struct {
	*fakeMeta
	mu   sync.Mutex
	ents []entity.Row
}

func (f *fakeMetaWithEntities) InsertEntities(_ context.Context, rows []entity.Row) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ents = append(f.ents, rows...)
	return nil
}

func TestIngestEntityExtraction(t *testing.T) {
	// 三行:同公网 IP 两行(去重)+ 私网一行(host_scoped)+ 一行无实体
	content := "8.8.8.8 - - [04/Aug/2026:00:00:01 +0800] \"GET /a HTTP/1.1\" 200 1 \"-\" \"UA\"\n" +
		"8.8.8.8 - - [04/Aug/2026:00:00:02 +0800] \"GET /b HTTP/1.1\" 200 1 \"-\" \"UA\"\n" +
		"192.168.1.10 - - [04/Aug/2026:00:00:03 +0800] \"GET /c HTTP/1.1\" 200 1 \"-\" \"UA\"\n"
	p := writeTemp(t, content)

	meta := &fakeMetaWithEntities{fakeMeta: newFakeMeta()}
	events := &fakeEvents{}
	spec := Spec{
		CaseName: "case-e", Path: p, Kind: KindText, Host: "h1",
		TZDeclared: "Asia/Shanghai", Workers: 2, BatchRows: 1000,
	}
	stats, err := IngestTextFile(context.Background(), meta, events, spec,
		"utf-8", descform.ParseNginxCombined, AlwaysBlockStart)
	if err != nil {
		t.Fatalf("摄入失败: %v", err)
	}
	if stats.Events != 3 {
		t.Fatalf("事件数 = %d, want 3", stats.Events)
	}
	// 实体:公网 8.8.8.8 去重一行 + 私网 host_scoped 一行
	if len(meta.ents) != 2 {
		t.Fatalf("实体数 = %d, want 2: %+v", len(meta.ents), meta.ents)
	}
	byKey := map[string]entity.Row{}
	for _, e := range meta.ents {
		byKey[e.CanonicalKey] = e
	}
	pub, ok := byKey["ip:8.8.8.8"]
	if !ok || pub.Qualifier != entity.QualGlobal || pub.Host != "h1" ||
		pub.LineNo != 1 { // 锚点保首见
		t.Fatalf("公网实体错: %+v", pub)
	}
	priv, ok := byKey["ip:192.168.1.10@h1"]
	if !ok || priv.Qualifier != entity.QualHostScoped {
		t.Fatalf("私网实体应 host_scoped 带主机后缀: %+v", priv)
	}
}

// 未实现 EntitySink 的 meta:摄入正常,零实体(向后兼容)。
func TestIngestNoEntitySink(t *testing.T) {
	p := writeTemp(t, "8.8.8.8 - - [04/Aug/2026:00:00:01 +0800] \"GET /a HTTP/1.1\" 200 1 \"-\" \"UA\"\n")
	meta := newFakeMeta()
	events := &fakeEvents{}
	spec := Spec{CaseName: "case-e2", Path: p, Kind: KindText,
		TZDeclared: "Asia/Shanghai", Workers: 1, BatchRows: 100, ChunkBytes: 4096}
	stats, err := IngestTextFile(context.Background(), meta, events, spec,
		"utf-8", descform.ParseNginxCombined, AlwaysBlockStart)
	if err != nil || stats.Events != 1 {
		t.Fatalf("无实体层摄入失败: stats=%+v err=%v", stats, err)
	}
}
