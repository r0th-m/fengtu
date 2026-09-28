// fengtu —— 丰图 server(上传接入 + 检索 + 待审区;Go 标准库 net/http)。
//
// 配置全走环境变量:
//
//	FENGTU_LISTEN        绑定地址(缺省 127.0.0.1:8200——运维口不外露,§9)
//	FENGTU_PG            PG DSN(postgres://user:pass@host:5432/fengtu)
//	FENGTU_CH            ClickHouse native 地址(host:9000)
//	FENGTU_CH_USER       CH 用户(缺省 fengtu)
//	FENGTU_CH_PASS       CH 口令
//	FENGTU_CH_COMPRESS   CH 传输压缩(缺省 lz4;none 见 store/ch.go)
//	FENGTU_DATA_DIR      数据根(缺省 ./data;金库 <dir>/vault,暂存 <dir>/tmp)
//	FENGTU_RULES_DIR     规则目录(缺省 configs/rules)
//	FENGTU_OPERATORS_DIR  算子注册表目录(缺省 configs/operators)
//	FENGTU_MAP           WinInfoSC 映射表(缺省 configs/wininfosc-map.yaml)
//	FENGTU_DESC_DIR      desc 目录(缺省 configs/desc)
//	FENGTU_COOKIE_SECURE 会话 cookie Secure 位(缺省 false;TLS 反代时置 true)
//	FENGTU_AI_API_KEY    AI 厂商 key(走 env 永不落库;亦可平台设置存 AES-GCM 密文)
//	FENGTU_AI_BASE_URL   AI base_url(OpenAI 线格式;缺省 https://api.deepseek.com/v1)
//	FENGTU_AI_MODEL      AI 模型(缺省 deepseek-chat)
//	FENGTU_AI_OUTBOUND   AI 外发总开关(true/1;缺省关=AI 端点 403 如实)
//	FENGTU_AI_BUDGET_TOKENS 会话 token 预算(缺省 20 万,超即熔断如实)
//	FENGTU_AI_SECRET     平台设置 API key 的 AES-GCM master key(不入库)
//	FENGTU_AI_PROVIDER   厂商标签(缺省 deepseek)
//	FENGTU_AI_MAX_TOKENS 厂商级单回复 token 上限(缺省 4096,切片六)
//	FENGTU_PLAYBOOKS_DIR  playbook 意图模板目录(缺省 configs/playbooks)
//	FENGTU_KB_DIR        启发式知识库内置条目目录(缺省 configs/kb)
//	FENGTU_INTENT_BUDGET_SECONDS 意图级 wall-clock 预算(缺省 600;耗尽→closed_exhausted 如实)
//	FENGTU_INTENT_TOKEN_BUDGET   意图 worker 会话 token 预算(缺省 100000)
//
// 启动顺序:PG 迁移(幂等)→ 连 CH → 金库/暂存 → 映射表/规则装载 →
// HTTP 监听。迁移失败/规则装载失败一律拒启,不带病上线。
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/ye-mengwen/fengtu/internal/agentloop"
	"github.com/ye-mengwen/fengtu/internal/auth"
	"github.com/ye-mengwen/fengtu/internal/fingerprint"
	"github.com/ye-mengwen/fengtu/internal/ingest"
	"github.com/ye-mengwen/fengtu/internal/ingest/store"
	"github.com/ye-mengwen/fengtu/internal/ingress"
	"github.com/ye-mengwen/fengtu/internal/intent"
	"github.com/ye-mengwen/fengtu/internal/kb"
	"github.com/ye-mengwen/fengtu/internal/logbuf"
	"github.com/ye-mengwen/fengtu/internal/operator"
	"github.com/ye-mengwen/fengtu/internal/query"
	"github.com/ye-mengwen/fengtu/internal/review"
	"github.com/ye-mengwen/fengtu/internal/vault"
	"github.com/ye-mengwen/fengtu/internal/web"
)

const version = "0.32.1-case-distilled"

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "启动失败: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 平台运行日志环形账(切片十,GET /api/logs 数据源):stdout 照常打
	// (systemd journal 持久),同时 tee 一份进进程内环形账(重启清零,如实)。
	logs := logbuf.New(2000)
	out := io.MultiWriter(os.Stdout, logs)

	dataDir := envOr("FENGTU_DATA_DIR", "data")

	meta, err := store.NewPG(ctx, os.Getenv("FENGTU_PG"))
	if err != nil {
		return err
	}
	defer meta.Close()
	if err := meta.Migrate(ctx); err != nil {
		return fmt.Errorf("schema 迁移失败: %w", err)
	}

	events, err := store.NewCH(ctx, os.Getenv("FENGTU_CH"),
		envOr("FENGTU_CH_USER", "fengtu"), os.Getenv("FENGTU_CH_PASS"),
		envOr("FENGTU_CH_COMPRESS", "lz4"))
	if err != nil {
		return err
	}
	defer events.Close()

	v, err := vault.Open(filepath.Join(dataDir, "vault"))
	if err != nil {
		return err
	}
	up, err := ingress.OpenManager(filepath.Join(dataDir, "tmp", "uploads"), 0)
	if err != nil {
		return err
	}

	mapText, err := os.ReadFile(envOr("FENGTU_MAP", "configs/wininfosc-map.yaml"))
	if err != nil {
		return fmt.Errorf("映射表读取失败: %w", err)
	}
	artifactMap, err := ingest.LoadArtifactMap(string(mapText))
	if err != nil {
		return err
	}

	rules, err := review.LoadRulesDir(envOr("FENGTU_RULES_DIR", "configs/rules"))
	if err != nil {
		return err
	}
	engine, err := review.NewEngine(rules, query.NewService(events), meta)
	if err != nil {
		return err
	}
	ops, err := operator.LoadDir(envOr("FENGTU_OPERATORS_DIR", "configs/operators"))
	if err != nil {
		return fmt.Errorf("算子注册表装载失败: %w", err)
	}
	engine.SetOperators(ops)

	descDir := envOr("FENGTU_DESC_DIR", "configs/desc")
	cands, err := fingerprint.LoadCandidates(descDir)
	if err != nil {
		return fmt.Errorf("指纹候选集装载失败: %w", err)
	}

	// AI 沟通骨架(切片五,§7):transcript 落 <data>/ai;治理闸(只读工具/
	// 预算熔断/外发同意/审计锚点)在 agentloop 收口。装配失败如实记、
	// AI 端点 503,不拖垮主服务。
	aiSvc := agentloop.NewService(agentloop.Deps{
		Meta: meta, Events: events, Query: query.NewService(events),
		Review: engine, ReviewStore: meta, Ops: ops, Vault: v, Audit: meta,
		TranscriptDir: filepath.Join(dataDir, "ai"),
		WorkspaceDir:  filepath.Join(dataDir, "workspace"), // 切片十三:案件工作区只读工具
		Recorder:      meta,                                // LLM 录制落库面(切片十;档位 ai_settings.record_mode)
	})
	if err := os.MkdirAll(filepath.Join(dataDir, "ai"), 0o755); err != nil {
		return fmt.Errorf("AI transcript 目录创建失败: %w", err)
	}

	// 意图链引擎(切片六,§6/§6.4):playbook 模板=数据(configs/playbooks);
	// planner 事件驱动;worker 单意图单 norma 会话(经 web 适配器接 agentloop,
	// 防 import 环)。模板装载失败拒启(与规则装载同纪律),引擎装配失败
	// 如实记、意图端点 503,不拖垮主服务。
	tpls, err := intent.LoadTemplatesDir(envOr("FENGTU_PLAYBOOKS_DIR", "configs/playbooks"))
	if err != nil {
		return fmt.Errorf("playbook 意图模板装载失败: %w", err)
	}

	// 启发式知识库(0.19.0):内置条目走 configs/kb/*.yaml(与 rules/desc/
	// playbooks 同套约定,装载失败拒启);用户条目与内置禁用态走 PG。
	kbBuiltin, err := kb.LoadBuiltinDir(envOr("FENGTU_KB_DIR", "configs/kb"))
	if err != nil {
		return fmt.Errorf("启发式知识库装载失败: %w", err)
	}
	kbSvc := kb.NewService(kbBuiltin, meta)

	intentEngine := intent.NewEngine(intent.Deps{
		Store: meta, Audit: meta, Templates: tpls,
		AI:            web.AIRunnerAdapter{AI: aiSvc},
		KB:            web.KBProviderAdapter{KB: kbSvc},
		BudgetSeconds: envInt("FENGTU_INTENT_BUDGET_SECONDS", intent.DefaultBudgetSeconds),
		TokenBudget:   int64(envInt("FENGTU_INTENT_TOKEN_BUDGET", intent.DefaultTokenBudget)),
		// worker 全局并发上限(切片十一):现读平台设置 ai_settings.agent_concurrency,
		// 配置页改动对之后的派发即时生效;读取失败如实落默认 4,不带病猜。
		ConcurrencyLimit: func() int {
			st, err := meta.GetAISettings(context.Background())
			if err != nil || st == nil || st.AgentConcurrency <= 0 {
				return intent.DefaultConcurrency
			}
			return st.AgentConcurrency
		},
		// 分支预算三闸(0.24.0-convergence):现读平台设置 ai_settings.
		// intent_*_limit,配置页改动对之后的派生即时生效;读取失败如实落
		// 默认 5/30/200,不带病猜(与并发上限同口径)。
		BudgetLimits: func() intent.BudgetLimits {
			l := intent.DefaultBudgetLimits()
			st, err := meta.GetAISettings(context.Background())
			if err != nil || st == nil {
				return l
			}
			if st.IntentFanoutLimit > 0 {
				l.Fanout = st.IntentFanoutLimit
			}
			if st.IntentChapterLimit > 0 {
				l.Chapter = st.IntentChapterLimit
			}
			if st.IntentCaseLimit > 0 {
				l.Case = st.IntentCaseLimit
			}
			return l
		},
	})
	intentEngine.Start(context.Background())
	defer intentEngine.Close()

	srv := web.NewServer(web.Deps{
		Auth:         auth.NewService(meta, 0),
		Meta:         meta,
		Audit:        meta,
		Vault:        v,
		Ingress:      up,
		Query:        query.NewService(events),
		Stats:        events, // 时间线聚合面(store.CH 同实现)
		Review:       engine,
		Events:       events,
		EventsAdmin:  events, // store.CH 同实现重解析删除面
		ArtifactMap:  artifactMap,
		DescDir:      descDir,
		StagingDir:   filepath.Join(dataDir, "tmp", "staging"),
		Candidates:   cands,
		Operators:    ops,
		AI:           aiSvc,
		Intent:       intentEngine,
		KB:           kbSvc,
		DataDir:      dataDir,
		Logs:         logs,
		Version:      version,
		CookieSecure: os.Getenv("FENGTU_COOKIE_SECURE") == "true",
	})

	listen := envOr("FENGTU_LISTEN", "127.0.0.1:8200")
	fmt.Fprintf(out, "丰图 server %s 监听 http://%s (规则 %d 条, 算子 %d 个, playbook %d 册, 知识库内置条目 %d 条)\n",
		version, listen, len(rules), len(ops.Specs()), len(tpls), kbSvc.BuiltinCount())
	return http.ListenAndServe(listen, srv.Handler())
}
