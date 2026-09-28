// Tip 数字口径悬停提示(§13:每个数字带出处,hover 显示计算口径)。
import { ReactNode } from "react";

export default function Tip({ text, children }: { text: string; children: ReactNode }) {
  return (
    <span className="relative group/tip inline-flex items-center cursor-help">
      {children}
      <span
        className="pointer-events-none absolute left-1/2 -translate-x-1/2 bottom-full mb-1.5
          hidden group-hover/tip:block z-50 w-max max-w-xs whitespace-normal
          rounded-lg bg-ink text-paper text-xs leading-relaxed px-2.5 py-1.5 shadow-card"
      >
        {text}
      </span>
    </span>
  );
}
