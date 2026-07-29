import { useState } from "react";
import { mn } from "../i18n/mn";
import { formatDateTime } from "../lib/formatDateTime";
import { deadlineLabel, STATUS_STYLE } from "../lib/incidentStatus";
import { IncidentDetailPanel } from "./IncidentDetailPanel";
import { RespondControl } from "./RespondControl";
import { SeverityEditor } from "./SeverityEditor";

export type IncidentCorrectiveAction = {
  id: string;
  description: string;
  addedByName: string;
  createdAt: string;
};

export type IncidentSeverityChange = {
  id: string;
  previousSeverity: string;
  newSeverity: string;
  reason: string;
  changedByName: string;
  createdAt: string;
};

export type IncidentAuditEntry = {
  id: string;
  action: string;
  actorName: string | null;
  details: string;
  createdAt: string;
};

export type IncidentDeadline = {
  deadlineAt: string;
  hoursAllowed: number;
  isOverdue: boolean;
  remainingSeconds: number;
};

export type Incident = {
  id: string;
  incidentId: string;
  detectedDate: string;
  occurredDate: string;
  reportedBy: string;
  systemLocation: string;
  incidentType: string;
  severity: string;
  l1Started: string;
  l2: string;
  l3: string;
  closed: string;
  resolutionTime: string;
  slaViolated: string;
  rootCause: string;
  description: string;
  createdAt: string;
  status: string;
  originalSeverity: string;
  registeredByName: string | null;
  deadline: IncidentDeadline;
  correctiveActions: IncidentCorrectiveAction[];
  severityHistory: IncidentSeverityChange[];
  auditTrail: IncidentAuditEntry[];
};

const SEVERITY_ACCENT: Record<string, string> = {
  "Бага": "border-l-success",
  "Дунд": "border-l-warning",
  "Өндөр": "border-l-danger",
  "Маш Өндөр": "border-l-danger",
};

const DEFAULT_SEVERITY_ACCENT = "border-l-border-strong";

export function IncidentCard({
  incident,
  onDelete,
  onChanged,
}: {
  incident: Incident;
  onDelete: (incident: Incident) => void;
  onChanged: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const accent = SEVERITY_ACCENT[incident.severity] ?? DEFAULT_SEVERITY_ACCENT;
  const lastPreviousSeverity = incident.severityHistory.at(-1)?.previousSeverity;
  const autoClosedNoResponse =
    !incident.closed && incident.correctiveActions.length === 0 && incident.deadline.isOverdue;

  return (
    <article className={`rounded-lg border border-border ${accent} border-l-4 bg-surface shadow-sm p-4 sm:p-5`}>
      <div
        className="flex flex-col sm:flex-row sm:items-start justify-between gap-3 cursor-pointer select-none"
        role="button"
        tabIndex={0}
        aria-expanded={expanded}
        onClick={() => setExpanded((v) => !v)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            setExpanded((v) => !v);
          }
        }}
      >
        <div className="min-w-0 space-y-1 flex items-start gap-2">
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
            className={`shrink-0 mt-1 text-muted transition-transform ${expanded ? "rotate-90" : ""}`}
          >
            <path d="M9 18l6-6-6-6" />
          </svg>
          <div className="min-w-0">
            <h3 className="text-sm truncate">
              <span className="font-medium text-text-secondary">{mn.incidentNumberLabel}</span>{" "}
              <span className="text-muted">{incident.incidentId}</span>
            </h3>
            <p className="text-xs truncate">
              <span className="font-medium text-text-secondary">{mn.incidentRegisteredDateLabel}</span>{" "}
              <span className="text-muted">{formatDateTime(incident.createdAt)}</span>
            </p>
            <p className="text-xs truncate">
              <span className="font-medium text-text-secondary">{mn.incidentRegisteredByLabel}</span>{" "}
              <span className="text-muted">{incident.registeredByName || mn.noValue}</span>
            </p>
          </div>
        </div>
        <div className="shrink-0 flex flex-col items-end gap-2">
          <div className="flex items-center flex-wrap justify-end gap-3">
            <span
              className={`inline-block rounded-full px-2.5 py-1 text-xs font-medium whitespace-nowrap ${
                STATUS_STYLE[incident.status] ?? "bg-surface-alt text-muted"
              }`}
            >
              {incident.status}
            </span>
            <span className="text-xs whitespace-nowrap">
              <span className="font-medium text-text-secondary">{mn.incidentDeadlineLabel}:</span>{" "}
              <span className="text-muted">
                {deadlineLabel(incident.deadline.remainingSeconds, incident.deadline.isOverdue)} (
                {incident.deadline.hoursAllowed}ц)
              </span>
            </span>
            <SeverityEditor
              incidentId={incident.id}
              currentSeverity={incident.severity}
              previousSeverity={lastPreviousSeverity}
              onChanged={onChanged}
            />
          </div>
          <RespondControl
            incidentId={incident.id}
            status={incident.status}
            autoClosedNoResponse={autoClosedNoResponse}
            onChanged={onChanged}
          />
        </div>
      </div>

      <div className="mt-3 space-y-2">
        <div>
          <p className="text-xs text-muted">{mn.incidentDescription}</p>
          <p className="text-sm text-text mt-0.5">{incident.description || mn.noValue}</p>
        </div>
        <div>
          <p className="text-xs text-muted">{mn.incidentSystemLocation}</p>
          <p className="text-sm text-text mt-0.5">{incident.systemLocation || mn.noValue}</p>
        </div>
      </div>

      {expanded && <IncidentDetailPanel incident={incident} onChanged={onChanged} />}

      <div className="mt-4 pt-3 border-t border-border flex items-center justify-end">
        <button onClick={() => onDelete(incident)} className="text-xs text-danger hover:underline">
          {mn.delete}
        </button>
      </div>
    </article>
  );
}
