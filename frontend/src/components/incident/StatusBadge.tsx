import { STATUS_STYLE } from "../../lib/incidentStatus";

export function StatusBadge({ status }: { status: string }) {
  if (!status) return null;
  return (
    <span
      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap ${
        STATUS_STYLE[status] ?? "bg-surface-alt text-muted border-border"
      }`}
    >
      {status}
    </span>
  );
}
