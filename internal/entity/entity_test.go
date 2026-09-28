// 实体归一化与抽取的焊死测试(语义基准:树庭 backend/app/entities.py)。
package entity

import (
	"testing"
)

func TestIPKey(t *testing.T) {
	cases := []struct {
		raw, host string
		wantKey   string
		wantQual  string
		wantOK    bool
	}{
		// 公网 → global,键无主机后缀
		{"8.8.8.8", "h1", "ip:8.8.8.8", QualGlobal, true},
		{" 1.2.3.4 ", "h1", "ip:1.2.3.4", QualGlobal, true},
		// 去端口(归一化规则:IP 去端口)
		{"1.2.3.4:443", "h1", "ip:1.2.3.4", QualGlobal, true},
		{"[2001:4860:4860::8888]:53", "h1", "ip:2001:4860:4860::8888", QualGlobal, true},
		// 私网 → host_scoped + @host 后缀(私网永不跨机)
		{"192.168.1.10", "h1", "ip:192.168.1.10@h1", QualHostScoped, true},
		{"10.0.0.2", "h2", "ip:10.0.0.2@h2", QualHostScoped, true},
		{"172.16.3.4", "h1", "ip:172.16.3.4@h1", QualHostScoped, true},
		{"127.0.0.1", "h1", "ip:127.0.0.1@h1", QualHostScoped, true},
		{"169.254.1.1", "h1", "ip:169.254.1.1@h1", QualHostScoped, true},
		{"fe80::1", "h1", "ip:fe80::1@h1", QualHostScoped, true},
		// 私网同值不同机 → 键不同(跨机匹配结构上不成立)
		// 未指定/组播不是「一台机器」的身份 → 不抽
		{"0.0.0.0", "h1", "", "", false},
		{"::", "h1", "", "", false},
		{"255.255.255.255", "h1", "", "", false}, // 非全局可达(受限广播)
		{"224.0.0.1", "h1", "", "", false},
		// 占位/非法 → 不抽
		{"-", "h1", "", "", false},
		{"", "h1", "", "", false},
		{"not-an-ip", "h1", "", "", false},
	}
	for _, c := range cases {
		got, ok := IPKey(c.raw, c.host)
		if ok != c.wantOK {
			t.Fatalf("IPKey(%q) ok=%v, want %v", c.raw, ok, c.wantOK)
		}
		if !ok {
			continue
		}
		if got.CanonicalKey != c.wantKey || got.Qualifier != c.wantQual {
			t.Fatalf("IPKey(%q) = (%q, %q), want (%q, %q)",
				c.raw, got.CanonicalKey, got.Qualifier, c.wantKey, c.wantQual)
		}
		if got.EntityType != TypeIP || got.RawValue == "" {
			t.Fatalf("IPKey(%q) 类型/留证缺失: %+v", c.raw, got)
		}
	}
	// 私网同值不同机键不同(跨机假联动的结构性防线)
	a, _ := IPKey("192.168.1.10", "h1")
	b, _ := IPKey("192.168.1.10", "h2")
	if a.CanonicalKey == b.CanonicalKey {
		t.Fatalf("私网同值跨机键相同: %q(假联动防线失守)", a.CanonicalKey)
	}
}

func TestDomainKey(t *testing.T) {
	cases := []struct{ raw, want string; ok bool }{
		{"Pan.Baidu.COM.", "dom:pan.baidu.com", true}, // 小写+去尾点
		{"mega.nz", "dom:mega.nz", true},
		{"a.b-c.example.com", "dom:a.b-c.example.com", true},
		{"localhost", "", false},     // 非 FQDN 结构不抽
		{"", "", false},
		{"-bad.com", "", false},
		{"bad..com", "", false},
	}
	for _, c := range cases {
		got, ok := DomainKey(c.raw)
		if ok != c.ok {
			t.Fatalf("DomainKey(%q) ok=%v, want %v", c.raw, ok, c.ok)
		}
		if ok && (got.CanonicalKey != c.want || got.Qualifier != QualGlobal) {
			t.Fatalf("DomainKey(%q) = %+v, want key %q global", c.raw, got, c.want)
		}
	}
}

func TestAccountKey(t *testing.T) {
	// SID 优先且大写归一,global
	c, ok := AccountKey("administrator", "s-1-5-21-100-200-500", "h1")
	if !ok || c.CanonicalKey != "acct:sid:S-1-5-21-100-200-500" || c.Qualifier != QualGlobal {
		t.Fatalf("SID 账户归一错: %+v ok=%v", c, ok)
	}
	// 无名有 SID 也成立(SID 即身份)
	c, ok = AccountKey("", "S-1-5-18", "h1")
	if !ok || c.CanonicalKey != "acct:sid:S-1-5-18" {
		t.Fatalf("裸 SID 归一错: %+v ok=%v", c, ok)
	}
	// 只有名 → 小写 + host_scoped
	c, ok = AccountKey("Administrator", "", "h1")
	if !ok || c.CanonicalKey != "acct:name:administrator@h1" || c.Qualifier != QualHostScoped {
		t.Fatalf("账户名归一错: %+v ok=%v", c, ok)
	}
	// 皆空 → 不抽
	if _, ok = AccountKey("", "", "h1"); ok {
		t.Fatal("无名无 SID 不应抽取")
	}
	// 伪 SID(结构不合)回退到名
	c, ok = AccountKey("bob", "S-1-5", "h1")
	if !ok || c.CanonicalKey != "acct:name:bob@h1" {
		t.Fatalf("伪 SID 回退错: %+v ok=%v", c, ok)
	}
}

func TestHashKey(t *testing.T) {
	h := "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
	c, ok := HashKey(h)
	if !ok || c.CanonicalKey != "hash:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ||
		c.Qualifier != QualGlobal {
		t.Fatalf("哈希归一错: %+v ok=%v", c, ok)
	}
	for _, bad := range []string{"", "abc", h[:63], h + "0", "zz3a5c4ac4a09c93a85d24730e3a62e3c0e1b415c966e36e2b19af0f26bb6d9b11"} {
		if _, ok := HashKey(bad); ok {
			t.Fatalf("非法哈希 %q 不应抽取", bad)
		}
	}
}

func TestExtract(t *testing.T) {
	// 顶层字段 + evtx data 子对象一层兜底 + 同键去重 + 私网排除是 qualifier
	// 语义(抽取,但 host_scoped)
	fields := `{
		"src_ip": "203.0.113.7",
		"remote_addr": "192.168.1.20",
		"data": {"IpAddress": "203.0.113.7", "TargetUserSid": "S-1-5-21-1-2-500",
			"TargetUserName": "Administrator"},
		"sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	}`
	got := Extract(fields, "h1")
	keys := map[string]Cand{}
	for _, c := range got {
		keys[c.CanonicalKey] = c
	}
	// 注:203.0.113.0/24 是 TEST-NET-3 文档段,netip 语义下属公网判定口径
	// 之外……(实测校准:netip.IsPrivate 不含文档段,故按 global 处理,
	// 与 operator publicIP 同口径)
	if _, ok := keys["ip:203.0.113.7"]; !ok {
		t.Fatalf("公网 IP 未抽取(顶层+data 去重): %v", keys)
	}
	if c, ok := keys["ip:192.168.1.20@h1"]; !ok || c.Qualifier != QualHostScoped {
		t.Fatalf("私网 IP 应 host_scoped 抽取: %v", keys)
	}
	if _, ok := keys["acct:sid:S-1-5-21-1-2-500"]; !ok {
		t.Fatalf("SID 账户未抽取: %v", keys)
	}
	// 同名账户带 SID → 只有 SID 键(SID 优先,不再产 name 键)
	if _, dup := keys["acct:name:administrator@h1"]; dup {
		t.Fatalf("有 SID 时不应再产 name 键: %v", keys)
	}
	if _, ok := keys["hash:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]; !ok {
		t.Fatalf("sha256 未抽取: %v", keys)
	}
	// 坏 JSON / 空 → 空,不炸
	if Extract("{oops", "h1") != nil || Extract("", "h1") != nil {
		t.Fatal("坏/空 fields 应零产出")
	}
}
