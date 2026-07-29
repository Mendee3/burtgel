const SEVERITY_BADGE_STYLE: Record<string, string> = {
  "Бага": "bg-success-light text-success",
  "Дунд": "bg-warning-light text-warning",
  "Өндөр": "bg-danger-light text-danger",
  "Маш Өндөр": "bg-danger text-white",
};

const DEFAULT_SEVERITY_BADGE_STYLE = "bg-surface-alt text-muted";

export function SeverityBadge({ severity, size = "md" }: { severity: string; size?: "sm" | "md" }) {
  const style = SEVERITY_BADGE_STYLE[severity] ?? DEFAULT_SEVERITY_BADGE_STYLE;
  const sizeClass = size === "sm" ? "px-2 py-0.5 text-[11px]" : "px-2.5 py-1 text-xs";
  return (
    <span className={`inline-block rounded-full font-medium whitespace-nowrap ${sizeClass} ${style}`}>
      {severity || "—"}
    </span>
  );
}
