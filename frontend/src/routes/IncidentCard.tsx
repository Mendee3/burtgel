import { useState, type ReactNode } from "react";
import { mn } from "../i18n/mn";
import { CalendarIcon, ChevronIcon, ServerIcon, UserIcon } from "../components/incident/icons";
import { SlaIndicator } from "../components/incident/SlaIndicator";
import { StatusBadge } from "../components/incident/StatusBadge";
import { formatDateTime } from "../lib/formatDateTime";
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

// Descriptions longer than this get clamped with a "read more" toggle.
const DESCRIPTION_CLAMP_CHARS = 180;

function MetaItem({ icon, label, value }: { icon: ReactNode; label: string; value: string }) {
  if (!value) return null;
  return (
    <span className="inline-flex min-w-0 items-center gap-1.5" title={label}>
      <span className="text-muted">{icon}</span>
      <span className="sr-only">{label}:</span>
      <span className="break-words">{value}</span>
    </span>
  );
}

export function IncidentCard({
  incident,
  onDelete,
  onChanged,
  canManage = true,
}: {
  incident: Incident;
  onDelete: (incident: Incident) => void;
  onChanged: () => void;
  canManage?: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const [descriptionOpen, setDescriptionOpen] = useState(false);
  const lastPreviousSeverity = incident.severityHistory.at(-1)?.previousSeverity;
  const autoClosedNoResponse =
    !incident.closed && incident.correctiveActions.length === 0 && incident.deadline.isOverdue;
  const title = incident.incidentType.trim();
  const description = incident.description.trim();
  const longDescription = description.length > DESCRIPTION_CLAMP_CHARS;
  const detailsId = `incident-details-${incident.id}`;

  return (
    <article className="rounded-xl border border-border bg-surface shadow-sm transition hover:shadow">
      <div className="p-4 sm:p-5">
        {/* Top row: ID, status, severity */}
        <div className="flex flex-wrap items-start justify-between gap-x-3 gap-y-2">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="font-mono text-sm font-semibold text-text break-all">{incident.incidentId}</span>
            <StatusBadge status={incident.status} />
          </div>
          <SeverityEditor
            incidentId={incident.id}
            currentSeverity={incident.severity}
            previousSeverity={lastPreviousSeverity}
            onChanged={onChanged}
            canManage={canManage}
          />
        </div>

        {/* Main: title, description, meta */}
        <div className="mt-2 space-y-1.5">
          {title && <h3 className="text-[15px] font-semibold leading-snug text-text break-words">{title}</h3>}
          {description && (
            <div>
              <p
                className={`text-sm leading-relaxed text-text-secondary whitespace-pre-line break-words ${
                  longDescription && !descriptionOpen ? "line-clamp-2" : ""
                }`}
              >
                {description}
              </p>
              {longDescription && (
                <button
                  type="button"
                  onClick={() => setDescriptionOpen((v) => !v)}
                  className="mt-0.5 rounded text-xs font-medium text-primary hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                >
                  {descriptionOpen ? mn.readLess : mn.readMore}
                </button>
              )}
            </div>
          )}
          {!title && !description && <p className="text-sm text-muted">{mn.noValue}</p>}

          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 pt-1 text-xs text-text-secondary">
            <MetaItem icon={<ServerIcon size={14} />} label={mn.incidentSystemLocation} value={incident.systemLocation} />
            <MetaItem
              icon={<CalendarIcon size={14} />}
              label={mn.incidentRegisteredAt}
              value={formatDateTime(incident.createdAt)}
            />
            <MetaItem
              icon={<UserIcon size={14} />}
              label={mn.incidentRegisteredBy}
              value={incident.registeredByName ?? ""}
            />
          </div>
        </div>
      </div>

      {expanded && (
        <div id={detailsId} className="px-4 pb-4 sm:px-5">
          <IncidentDetailPanel incident={incident} onChanged={onChanged} />
        </div>
      )}

      {/* Bottom row: SLA, respond, actions */}
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 rounded-b-xl border-t border-border bg-surface-alt/60 px-4 py-2.5 sm:px-5">
        <SlaIndicator deadline={incident.deadline} status={incident.status} />
        <div className="flex flex-wrap items-center justify-end gap-x-3 gap-y-2">
          <RespondControl
            incidentId={incident.id}
            status={incident.status}
            autoClosedNoResponse={autoClosedNoResponse}
            onChanged={onChanged}
            canManage={canManage}
          />
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            aria-expanded={expanded}
            aria-controls={detailsId}
            className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-xs font-medium text-primary hover:bg-primary-light focus:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            {expanded ? mn.incidentHideDetails : mn.incidentViewDetails}
            <ChevronIcon size={14} className={`transition-transform ${expanded ? "-rotate-90" : "rotate-90"}`} />
          </button>
          {canManage && (
            <button
              type="button"
              onClick={() => onDelete(incident)}
              className="rounded-md px-2 py-1 text-xs text-danger hover:bg-danger-light focus:outline-none focus-visible:ring-2 focus-visible:ring-danger"
            >
              {mn.delete}
            </button>
          )}
        </div>
      </div>
    </article>
  );
}

export function IncidentCardSkeleton() {
  return (
    <div className="rounded-xl border border-border bg-surface p-4 shadow-sm animate-pulse sm:p-5">
      <div className="flex justify-between">
        <div className="h-4 w-40 rounded bg-surface-alt" />
        <div className="h-5 w-20 rounded-full bg-surface-alt" />
      </div>
      <div className="mt-3 h-4 w-2/3 rounded bg-surface-alt" />
      <div className="mt-2 h-3 w-full rounded bg-surface-alt" />
      <div className="mt-4 h-3 w-1/2 rounded bg-surface-alt" />
    </div>
  );
}
