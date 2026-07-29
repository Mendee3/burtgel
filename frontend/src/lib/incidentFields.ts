export type IncidentFieldOption = { label: string; value: string };
export type IncidentFieldDef = {
  key: string;
  label: string;
  required: boolean;
  kind: "text" | "textarea" | "select" | "date";
  options?: IncidentFieldOption[];
};

const toOptions = (values: string[]): IncidentFieldOption[] => values.map((v) => ({ label: v, value: v }));

export const INCIDENT_FIELDS: IncidentFieldDef[] = [
  { key: "detectedDate", label: "Огноо / Илэрсэн", required: true, kind: "date" },
  { key: "occurredDate", label: "Үүссэн / Таамаг", required: false, kind: "date" },
  { key: "reportedBy", label: "Мэдээлсэн", required: false, kind: "date" },
  { key: "systemLocation", label: "Систем / Байршил", required: false, kind: "text" },
  { key: "incidentType", label: "Төрөл", required: false, kind: "text" },
  { key: "severity", label: "Severity", required: false, kind: "select", options: toOptions(["Бага", "Дунд", "Өндөр", "Маш Өндөр"]) },
  { key: "l1Started", label: "L1 эхэлсэн", required: false, kind: "text" },
  { key: "l2", label: "L2", required: false, kind: "text" },
  { key: "l3", label: "L3", required: false, kind: "text" },
  { key: "closed", label: "Хаасан", required: false, kind: "date" },
  { key: "resolutionTime", label: "Шийдвэрлэх хугацаа", required: false, kind: "text" },
  { key: "slaViolated", label: "SLA зөрчсөн", required: false, kind: "select", options: toOptions(["Тийм", "Үгүй"]) },
  { key: "rootCause", label: "Root Cause", required: false, kind: "textarea" },
  { key: "description", label: "Тайлбар", required: false, kind: "textarea" },
];

const RESOLUTION_HOURS_RANGE: Record<string, [number, number]> = {
  "Маш Өндөр": [3, 6],
  "Өндөр": [6, 12],
  "Дунд": [24, 48],
  "Бага": [48, 72],
};

export function resolutionTimeForSeverity(severity: string): string {
  const range = RESOLUTION_HOURS_RANGE[severity];
  if (!range) return "";
  return `${range[0]}–${range[1]} цаг`;
}
