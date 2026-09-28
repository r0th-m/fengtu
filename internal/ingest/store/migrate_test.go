// 迁移文件双入口焊死:内嵌 migrations/*.sql 必须与 deploy/schema/pg/*.sql
// 逐字节一致(全新部署走 docker initdb,既有库走 server Migrate——
// 两条路不许漂移)。
package store

import (
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
)

func deploySchemaDir(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller 失败")
	}
	// 本文件在 internal/ingest/store/,仓根向上三级
	root := filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(thisFile))))
	return filepath.Join(root, "deploy", "schema", "pg")
}

func TestMigrationsMatchDeploySchema(t *testing.T) {
	dir := deploySchemaDir(t)
	deployEntries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("deploy schema 目录读取失败: %v", err)
	}
	var deployNames []string
	for _, e := range deployEntries {
		if filepath.Ext(e.Name()) == ".sql" {
			deployNames = append(deployNames, e.Name())
		}
	}
	embedEntries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("内嵌迁移目录读取失败: %v", err)
	}
	var embedNames []string
	for _, e := range embedEntries {
		embedNames = append(embedNames, e.Name())
	}
	sort.Strings(deployNames)
	sort.Strings(embedNames)
	if len(deployNames) != len(embedNames) {
		t.Fatalf("迁移文件集漂移: deploy=%v embedded=%v", deployNames, embedNames)
	}
	for i, name := range deployNames {
		if embedNames[i] != name {
			t.Fatalf("迁移文件名漂移: deploy=%v embedded=%v", deployNames, embedNames)
		}
		deployBytes, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("%s 读取失败: %v", name, err)
		}
		embedBytes, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatalf("%s 内嵌读取失败: %v", name, err)
		}
		if string(deployBytes) != string(embedBytes) {
			t.Fatalf("%s 内容漂移: deploy/schema/pg 与内嵌副本不一致——"+
				"改完 deploy 侧必须同步 internal/ingest/store/migrations/", name)
		}
	}
}
