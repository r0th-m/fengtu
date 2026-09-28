// 多行块边界探测(摄入管线分块对齐用)。
//
// 管线按 ≥64MB 分块并行解析(DESIGN §4.1),块界必须落在多行块起始行上,
// 否则一个堆栈块会被拦腰切成「前半事件 + 后半孤儿」。引擎内部已有多行
// 状态机,这里只暴露「该行是否块起始」的判定,状态机本身不外漏。
package descform

// IsBlockStart 报告一行是否多行块起始;无 multiline 声明的格式每行都是
// 独立记录,恒 true(任意行界都是安全切点)。
func (d *CompiledDesc) IsBlockStart(line string) bool {
	if d.startRe == nil {
		return true
	}
	return matchAt(d.startRe, line) != nil
}
