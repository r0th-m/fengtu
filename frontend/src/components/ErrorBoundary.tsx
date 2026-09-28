// ErrorBoundary 渲染崩溃兜底(探索链路白屏事故后立):子树渲染异常时
// 不再整页白屏——就地显示错误原文 + 「刷新页面」按钮,其余面板不受影响。
// (React 错误边界只能类组件;错误原文如实呈现,不包装。)
import { Component, type ReactNode } from "react";

interface Props {
  children: ReactNode;
  title?: string; // 面板名(如「探索链路」)
}

interface State {
  err: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { err: null };

  static getDerivedStateFromError(err: Error): State {
    return { err };
  }

  componentDidCatch(err: Error, info: unknown) {
    console.error("[ErrorBoundary]", this.props.title || "", err, info);
  }

  render() {
    const { err } = this.state;
    if (err) {
      return (
        <div className="rounded-card bg-white shadow-card p-8 text-center space-y-3">
          <div className="text-sm font-medium text-red-600">
            {this.props.title || "面板"}渲染出错(如实,整页未崩)
          </div>
          <div className="text-xs text-mute font-mono break-all max-w-2xl mx-auto">
            {String(err.message || err)}
          </div>
          <button
            onClick={() => window.location.reload()}
            className="rounded-lg bg-brand text-white text-xs font-medium px-4 py-2
              hover:bg-brand-dark transition-colors"
            data-testid="error-boundary-reload"
          >
            刷新页面
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}
