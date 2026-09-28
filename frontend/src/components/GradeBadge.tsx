// 候选等级 badge(§13:「疑似/待复核」是视觉一等公民;「确认」类措辞禁出现)。
// 三档:strong 强疑似 / suspect 疑似 / weak 弱信号;色=等级色。
import Tip from "./Tip";

const STYLES: Record<string, { label: string; cls: string; tip: string }> = {
  strong: {
    label: "强疑似",
    cls: "bg-red-50 text-red-700 ring-red-200",
    tip: "证据等级 strong:系统按证据结构计算(命中字段语义+来源可信度),非结论,判断权归人",
  },
  suspect: {
    label: "疑似",
    cls: "bg-amber-50 text-amber-700 ring-amber-200",
    tip: "证据等级 suspect:系统按证据结构计算,待人工复核,非结论",
  },
  weak: {
    label: "弱信号",
    cls: "bg-sky-50 text-sky-700 ring-sky-200",
    tip: "证据等级 weak:弱信号,线索价值,需人工判断是否跟进",
  },
};

const SEV_STYLES: Record<string, string> = {
  high: "bg-red-600/10 text-red-700 ring-red-300",
  medium: "bg-amber-500/10 text-amber-700 ring-amber-300",
  low: "bg-slate-400/10 text-slate-600 ring-slate-300",
  info: "bg-slate-400/10 text-slate-500 ring-slate-200",
};

export function GradeBadge({ grade }: { grade: string }) {
  const s = STYLES[grade] || {
    label: grade || "未定级",
    cls: "bg-slate-100 text-slate-600 ring-slate-200",
    tip: "证据等级由系统按证据结构计算(如实:该候选无等级字段)",
  };
  return (
    <Tip text={s.tip}>
      <span className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ${s.cls}`}>
        {s.label}
      </span>
    </Tip>
  );
}

export function SeverityDot({ severity }: { severity: string }) {
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[11px] ring-1 ${SEV_STYLES[severity] || SEV_STYLES.info}`}>
      {severity}
    </span>
  );
}
