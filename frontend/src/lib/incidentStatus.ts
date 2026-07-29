export const STATUS_STYLE: Record<string, string> = {
  "Нээлттэй": "bg-primary-light text-primary",
  "Хариу арга хэмжээ авсан": "bg-success-light text-success",
  "Хаагдсан": "bg-surface-alt text-muted",
};

const ACTION_LABELS: Record<string, string> = {
  create: "Бүртгэсэн",
  update: "Талбар шинэчилсэн",
  corrective_action: "Хариу арга хэмжээ нэмсэн",
  delete: "Устгасан",
};

export function auditActionLabel(action: string): string {
  return ACTION_LABELS[action] ?? action;
}

export function formatDuration(totalSeconds: number): string {
  const seconds = Math.abs(Math.round(totalSeconds));
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const parts: string[] = [];
  if (days > 0) parts.push(`${days}хон`);
  if (hours > 0) parts.push(`${hours}ц`);
  if (days === 0 && minutes > 0) parts.push(`${minutes}м`);
  return parts.length > 0 ? parts.join(" ") : "1м";
}

export function deadlineLabel(remainingSeconds: number, isOverdue: boolean): string {
  const duration = formatDuration(remainingSeconds);
  return isOverdue ? `${duration} хэтэрсэн` : `${duration} үлдсэн`;
}
