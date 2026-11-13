import type { ReactNode } from "react";

const TONE_STYLE: Record<string, string> = {
  primary: "bg-primary-light text-primary",
  info: "bg-sky-50 text-sky-700",
  danger: "bg-red-50 text-red-700",
  severe: "bg-orange-50 text-orange-700",
};

export function KpiCard({
  label,
  value,
  hint,
  icon,
  tone,
  active,
  onClick,
}: {
  label: string;
  value: number;
  hint: string;
  icon: ReactNode;
  tone: keyof typeof TONE_STYLE;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`group flex h-full items-start justify-between gap-3 rounded-xl border bg-surface p-4 text-left shadow-sm transition hover:border-primary-border hover:shadow focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2 ${
        active ? "border-primary ring-1 ring-primary" : "border-border"
      }`}
    >
      <div className="min-w-0">
        <p className="text-xs font-medium text-text-secondary">{label}</p>
        <p className="mt-1 text-2xl font-semibold tabular-nums text-text">{value}</p>
        <p className="mt-1 text-xs text-muted">{hint}</p>
      </div>
      <span className={`flex h-9 w-9 shrink-0 items-center justify-center rounded-lg ${TONE_STYLE[tone]}`}>
        {icon}
      </span>
    </button>
  );
}

export function KpiCardSkeleton() {
  return (
    <div className="h-[104px] rounded-xl border border-border bg-surface p-4 shadow-sm animate-pulse">
      <div className="h-3 w-24 rounded bg-surface-alt" />
      <div className="mt-3 h-6 w-10 rounded bg-surface-alt" />
      <div className="mt-3 h-3 w-32 rounded bg-surface-alt" />
    </div>
  );
}
