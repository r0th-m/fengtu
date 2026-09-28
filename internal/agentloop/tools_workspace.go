// 工作区只读工具(切片十三,案件工作区隔离):用户在案件工作区(页面
// 「工作空间」选案件进入,或案件页「工作区」tab)上传的补充材料,AI 会话
// 经 workspace_list/workspace_read 只读可见——用户在对应任务里说
// 「我在你的工作空间里传了 xx 文件,你读取一下」的落点。
//
// 纪律(与 web 端点同一套底线,internal/workspace 唯一真源):
//   - 作用域=当前会话案件的工作区目录(WorkspaceDir/<case_id>),路径净化
//     + 符号链接逃逸检查全走 workspace.Resolve,模型给不出别的案件;
//   - 只读:不注册任何写工具;读操作不落证据审计(与页面读口径一致,
//     审计只记工具调用行——PostToolUse hook 已有);
//   - 防 token 爆炸:read 上限 256KB,超出截断如实标 truncated;
//     二进制按内容嗅探(workspace.LooksBinary)如实拒读;
//   - 口径写进工具描述:工作区材料是用户提供的参考,不是采集证据;
//     引用其内容须说明来自用户工作区,锚点纪律不变(锚点只能锚采集物)。
package agentloop

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/Autumn-27/norma/tool"

	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/workspace"
)

// wsToolReadMaxBytes workspace_read 单次上限(256KB,防 token 爆炸;
// 超出截断如实标)。wsToolListMaxEntries workspace_list 单目录条目上限。
const (
	wsToolReadMaxBytes    = 256 << 10
	wsToolListMaxEntries  = 500
	wsToolScopeDisclaimer = "这是用户在案件工作区上传的补充材料,属于用户提供的参考," +
		"不是采集证据;引用其内容时须说明来自用户工作区,锚点纪律不变" +
		"(一切结论的锚点仍只能锚案件采集物 source_id+line_no)"
)

// wsCaseRoot 会话案件工作区根(案件 id 过 Resolve 单段净化,纵深防御)。
func (s *Service) wsCaseRoot(sess *store.AISession) (string, error) {
	return workspace.Resolve(s.deps.WorkspaceDir, sess.CaseID)
}

// toolWorkspaceList 列案件工作区目录(空目录/未建如实返回空)。
func (s *Service) toolWorkspaceList(sess *store.AISession) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "workspace_list",
		Description: "列当前案件工作区目录(用户补充材料的存放处;path=相对案件" +
			"工作区根的 slash 路径,空=根)。工作区尚未建/目录不存在时如实返回空清单。" +
			wsToolScopeDisclaimer,
		Schema: objSchema(map[string]any{
			"path": strProp("相对路径(可空=案件工作区根)"),
		}),
		ReadOnly: readonly, Concurrent: readonly, Permissions: allowAll,
		Run: func(ctx context.Context, input json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var p struct {
				Path string `json:"path"`
			}
			if err := decode(input, &p); err != nil {
				return tool.Errorf(err.Error()), nil
			}
			root, err := s.wsCaseRoot(sess)
			if err != nil {
				return tool.Errorf("案件工作区解析失败: "+err.Error()), nil
			}
			fp, err := workspace.Resolve(root, p.Path)
			if err != nil {
				return tool.Errorf(err.Error()), nil
			}
			des, err := os.ReadDir(fp)
			if err != nil {
				if os.IsNotExist(err) {
					// 空目录/未建:如实空,不报错(用户可能还没传材料)
					return asJSON(map[string]any{
						"path": p.Path, "entries": []map[string]any{},
						"note": "案件工作区此目录不存在(用户尚未上传补充材料);" +
							wsToolScopeDisclaimer,
					})
				}
				return tool.Errorf("目录读取失败: "+err.Error()), nil
			}
			entries := make([]map[string]any, 0, len(des))
			for _, de := range des {
				info, err := de.Info()
				if err != nil {
					continue // 竞态删除:跳过
				}
				ep := de.Name()
				if p.Path != "" {
					ep = p.Path + "/" + de.Name()
				}
				entries = append(entries, map[string]any{
					"name": de.Name(), "path": ep, "dir": de.IsDir(),
					"size": info.Size(), "mtime": info.ModTime().UnixMilli(),
				})
			}
			sort.Slice(entries, func(i, j int) bool {
				if entries[i]["dir"] != entries[j]["dir"] {
					return entries[i]["dir"].(bool)
				}
				return entries[i]["name"].(string) < entries[j]["name"].(string)
			})
			truncated := false
			if len(entries) > wsToolListMaxEntries {
				entries = entries[:wsToolListMaxEntries]
				truncated = true
			}
			return asJSON(map[string]any{
				"path": p.Path, "entries": entries, "truncated": truncated,
				"note": wsToolScopeDisclaimer,
			})
		},
	})
}

// toolWorkspaceRead 读案件工作区文本文件(≤256KB;二进制如实拒,超大截断)。
func (s *Service) toolWorkspaceRead(sess *store.AISession) tool.CoreTool {
	return tool.Build(tool.Spec{
		Name: "workspace_read",
		Description: "读当前案件工作区里的文本文件(path=相对案件工作区根的 slash " +
			"路径,workspace_list 可得)。二进制(按内容嗅探,非扩展名)如实拒读;" +
			"超 256KB 截断返回并标 truncated(防 token 爆炸)。" + wsToolScopeDisclaimer,
		Schema: objSchema(map[string]any{
			"path": strProp("相对案件工作区根的文件路径"),
		}, "path"),
		ReadOnly: readonly, Concurrent: readonly, Permissions: allowAll,
		Run: func(ctx context.Context, input json.RawMessage, _ *tool.ToolContext) (tool.Result, error) {
			var p struct {
				Path string `json:"path"`
			}
			if err := decode(input, &p); err != nil {
				return tool.Errorf(err.Error()), nil
			}
			if p.Path == "" {
				return tool.Errorf("path 必填"), nil
			}
			root, err := s.wsCaseRoot(sess)
			if err != nil {
				return tool.Errorf("案件工作区解析失败: "+err.Error()), nil
			}
			fp, err := workspace.Resolve(root, p.Path)
			if err != nil {
				return tool.Errorf(err.Error()), nil
			}
			info, err := os.Stat(fp)
			if err != nil {
				if os.IsNotExist(err) {
					return tool.Errorf("无此文件(案件工作区): "+p.Path), nil
				}
				return tool.Errorf("读取失败: "+err.Error()), nil
			}
			if info.IsDir() {
				return tool.Errorf("目录不能按文件读: "+p.Path+"(用 workspace_list)"), nil
			}
			f, err := os.Open(fp)
			if err != nil {
				return tool.Errorf("读取失败: "+err.Error()), nil
			}
			defer f.Close()
			// 读 cap+1 判定截断(不全量进内存:超大文件也不能烧内存)
			buf := make([]byte, wsToolReadMaxBytes+1)
			n, err := io.ReadFull(f, buf)
			if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
				return tool.Errorf("读取失败: "+err.Error()), nil
			}
			data := buf[:n]
			truncated := n > wsToolReadMaxBytes
			if truncated {
				data = data[:wsToolReadMaxBytes]
			}
			if workspace.LooksBinary(data) {
				return tool.Errorf("二进制文件(按内容嗅探,非扩展名)如实拒读: " +
					p.Path + ";需要用户自行提取文本后再传"), nil
			}
			return asJSON(map[string]any{
				"path": p.Path, "size": info.Size(), "truncated": truncated,
				"content": strings.ToValidUTF8(string(data), ""),
				"note": wsToolScopeDisclaimer,
			})
		},
	})
}
