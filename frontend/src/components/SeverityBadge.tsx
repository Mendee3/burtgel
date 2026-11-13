const SEVERITY_BADGE_STYLE: Record<string, { badge: string; dot: string }> = {
  "Маш Өндөр": { badge: "bg-red-50 text-red-700 ring-red-200", dot: "bg-red-600" },
  "Өндөр": { badge: "bg-orange-50 text-orange-700 ring-orange-200", dot: "bg-orange-500" },
  "Дунд": { badge: "bg-amber-50 text-amber-800 ring-amber-200", dot: "bg-amber-500" },
  "Бага": { badge: "bg-slate-100 text-slate-700 ring-slate-200", dot: "bg-slate-400" },
};

const DEFAULT_SEVERITY_BADGE_STYLE = { badge: "bg-surface-alt text-muted ring-border", dot: "bg-border-strong" };

export function SeverityBadge({ severity, size = "md" }: { severity: string; size?: "sm" | "md" }) {
  const style = SEVERITY_BADGE_STYLE[severity] ?? DEFAULT_SEVERITY_BADGE_STYLE;
  const sizeClass = size === "sm" ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-0.5 text-xs";
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full font-medium whitespace-nowrap ring-1 ring-inset ${sizeClass} ${style.badge}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${style.dot}`} aria-hidden="true" />
      {severity || "—"}
    </span>
  );
}
