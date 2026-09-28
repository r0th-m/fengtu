// WinInfoSC 采集包结构映射(解析器对 spec 写:映射规则是 YAML 数据,
// 不写死代码;新增采集项只改 YAML)。
//
// 映射表语义:
//   - package_root_regex:采集包根目录名规范(Forensic_<IP>_<主机名>),
//     不匹配即「这不是 WinInfoSC 包」,如实拒绝,不猜;
//   - rules 自上而下首条命中即停;match 含路径分隔符时匹配包内相对路径
//     (正斜杠),否则只匹配文件名;
//   - route:evtx_native(纯 Go 库原生解析)| desc(绑定描述文件,
//     desc 字段给描述名)| native(树庭面原生解析器,parser 字段给
//     解析器名:registry_hive/mft/prefetch/lnk/usn_csv,见
//     internal/parsers)| raw(原文登记不解析);
//   - log_type(可选):源品类声明(适用域路由键,词表见
//     descform.LogTypes;如 usn_csv 规则声明 usn_journal);
//   - 没有任何规则命中 → 兜底 raw + artifact "unmapped"(如实计数,
//     映射表覆盖度一眼可查)。
package ingest

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/ye-mengwen/fengtu/internal/descform"
)

// Route 摄入路由。
type Route string

const (
	RouteEVTXNative Route = "evtx_native"
	RouteDesc       Route = "desc"
	RouteNative     Route = "native"
	RouteRaw        Route = "raw"
)

// MapRule 一条映射规则。
type MapRule struct {
	Match    string `yaml:"match"`
	Artifact string `yaml:"artifact"`
	Route    Route  `yaml:"route"`
	Desc     string `yaml:"desc,omitempty"`
	Parser   string `yaml:"parser,omitempty"`   // route=native 必填(internal/parsers 注册名)
	LogType  string `yaml:"log_type,omitempty"` // 源品类声明(可选,词表见 descform.LogTypes)
}

// ArtifactMap 映射表。
type ArtifactMap struct {
	Name             string    `yaml:"name"`
	Title            string    `yaml:"title"`
	PackageRootRegex string    `yaml:"package_root_regex"`
	// HostRegex 主机标识提取(一案多包,§3 修正稿):从包根目录名提取
	// 主机键,命名捕获组 ?P<host>;不声明/不匹配 = 主机未建模(空串,如实)。
	HostRegex string    `yaml:"host_regex"`
	Rules     []MapRule `yaml:"rules"`

	rootRe *regexp.Regexp
	hostRe *regexp.Regexp
}

// LoadArtifactMap 加载并校验映射表。
func LoadArtifactMap(yamlText string) (*ArtifactMap, error) {
	var m ArtifactMap
	if err := yaml.Unmarshal([]byte(yamlText), &m); err != nil {
		return nil, fmt.Errorf("映射表 YAML 解析失败: %w", err)
	}
	if m.PackageRootRegex == "" {
		return nil, fmt.Errorf("映射表缺 package_root_regex")
	}
	re, err := regexp.Compile(m.PackageRootRegex)
	if err != nil {
		return nil, fmt.Errorf("package_root_regex 编译失败: %w", err)
	}
	m.rootRe = re
	if m.HostRegex != "" {
		hre, err := regexp.Compile(m.HostRegex)
		if err != nil {
			return nil, fmt.Errorf("host_regex 编译失败: %w", err)
		}
		if hre.SubexpIndex("host") < 0 {
			return nil, fmt.Errorf("host_regex 须含命名捕获组 (?P<host>...)")
		}
		m.hostRe = hre
	}
	for i, r := range m.Rules {
		if r.Match == "" {
			return nil, fmt.Errorf("规则 #%d 缺 match", i+1)
		}
		switch r.Route {
		case RouteEVTXNative, RouteRaw:
		case RouteDesc:
			if r.Desc == "" {
				return nil, fmt.Errorf("规则 #%d route=desc 缺 desc 名", i+1)
			}
		case RouteNative:
			if r.Parser == "" {
				return nil, fmt.Errorf("规则 #%d route=native 缺 parser 名", i+1)
			}
		default:
			return nil, fmt.Errorf("规则 #%d 未知 route: %q", i+1, r.Route)
		}
		if r.Artifact == "" {
			return nil, fmt.Errorf("规则 #%d 缺 artifact", i+1)
		}
		if r.LogType != "" && !descform.LogTypes[r.LogType] {
			return nil, fmt.Errorf("规则 #%d log_type 未知: %q(词表见 descform.LogTypes)",
				i+1, r.LogType)
		}
	}
	return &m, nil
}

// IsPackageRoot 判定目录名是否符合采集包命名规范。
func (m *ArtifactMap) IsPackageRoot(dirName string) bool {
	return m.rootRe.MatchString(dirName)
}

// HostOfPackage 从包根目录名提取主机键(host_regex 命名组 host;未声明/
// 不匹配 → 空串=主机未建模,如实;LinuxSC/strata 同语义,只改 YAML)。
func (m *ArtifactMap) HostOfPackage(packageName string) string {
	if m.hostRe == nil {
		return ""
	}
	match := m.hostRe.FindStringSubmatch(packageName)
	if match == nil {
		return ""
	}
	return match[m.hostRe.SubexpIndex("host")]
}

// Match 匹配包内相对路径(正斜杠)→ 规则;无命中返回 nil(调用方按
// 兜底 raw + "unmapped" 处理)。
func (m *ArtifactMap) Match(relPath string) *MapRule {
	relPath = path.Clean(relPath)
	base := path.Base(relPath)
	for i := range m.Rules {
		r := &m.Rules[i]
		target := r.Match
		if strings.ContainsRune(target, '/') {
			if ok, _ := path.Match(target, relPath); ok {
				return r
			}
			continue
		}
		if ok, _ := path.Match(target, base); ok {
			return r
		}
	}
	return nil
}
