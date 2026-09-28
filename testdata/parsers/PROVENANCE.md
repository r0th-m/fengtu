# testdata/parsers 夹具来源

- `NTUSER.DAT`：复制自 `www.velocidex.com/golang/regparser`
  (v0.0.0-20250203141505-31e704a67ef7) 的 `testdata/NTUSER.DAT`,
  Apache-2.0 许可。用途：registry hive 解析器的合成基准夹具(树庭面
  真实 hive 含用户痕迹,按纪律永不入库,故用库自带测试夹具)。
- 其余解析器(prefetch/lnk/usn/mft)的合成夹具由
  `internal/parsers/parsers_test.go` 内联生成(对 spec 写字节级构造)。
