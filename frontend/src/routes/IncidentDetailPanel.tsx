import { useState } from "react";
import { SeverityBadge } from "../components/SeverityBadge";
import { mn } from "../i18n/mn";
import { formatDateTime } from "../lib/formatDateTime";
import { auditActionLabel } from "../lib/incidentStatus";
import type { Incident } from "./IncidentCard";
import { IncidentForm } from "./IncidentForm";

const SHOW_EDIT_FIELDS_BUTTON = false;

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs font-medium text-text-secondary">{label}</dt>
      <dd className="text-sm text-muted mt-0.5">{value || mn.noValue}</dd>
    </div>
  );
}

type HistoryItem =
  | { kind: "audit"; key: string; label: string; actor: string; createdAt: string }
  | {
      kind: "severity";
      key: string;
      previousSeverity: string;
      newSeverity: string;
      reason: string;
      actor: string;
      createdAt: string;
    }
  | { kind: "corrective_action"; key: string; description: string; actor: string; createdAt: string };

export function IncidentDetailPanel({ incident, onChanged }: { incident: Incident; onChanged: () => void }) {
  const [editingFields, setEditingFields] = useState(false);

  const combinedHistory: HistoryItem[] = [
    ...incident.auditTrail
      .filter((a) => a.action !== "severity_change" && a.action !== "corrective_action" && a.action !== "create")
      .map((a): HistoryItem => ({
        kind: "audit",
        key: `audit-${a.id}`,
        label: auditActionLabel(a.action),
        actor: a.actorName ?? mn.noValue,
        createdAt: a.createdAt,
      })),
    ...incident.severityHistory.map((h): HistoryItem => ({
      kind: "severity",
      key: `sev-${h.id}`,
      previousSeverity: h.previousSeverity,
      newSeverity: h.newSeverity,
      reason: h.reason,
      actor: h.changedByName,
      createdAt: h.createdAt,
    })),
    ...incident.correctiveActions.map((a): HistoryItem => ({
      kind: "corrective_action",
      key: `action-${a.id}`,
      description: a.description,
      actor: a.addedByName,
      createdAt: a.createdAt,
    })),
  ].sort((a, b) => a.createdAt.localeCompare(b.createdAt));

  if (editingFields) {
    return (
      <div className="mt-4 pt-4 border-t border-border">
        <IncidentForm
          incident={incident}
          onSaved={() => {
            setEditingFields(false);
            onChanged();
          }}
          onCancel={() => setEditingFields(false)}
        />
      </div>
    );
  }

  return (
    <div className="mt-4 pt-4 border-t border-border space-y-5">
      {/* Original field details */}
      <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <DetailRow label={mn.incidentDetectedDate} value={incident.detectedDate} />
        <DetailRow label={mn.incidentOccurredDate} value={incident.occurredDate} />
        <DetailRow label={mn.incidentReportedBy} value={incident.reportedBy} />
        <DetailRow label={mn.incidentType} value={incident.incidentType} />
        <DetailRow label={mn.incidentL1Started} value={incident.l1Started} />
        <DetailRow label="L2" value={incident.l2} />
        <DetailRow label="L3" value={incident.l3} />
        <DetailRow label={mn.incidentClosed} value={incident.closed} />
        <DetailRow label={mn.incidentResolutionTime} value={incident.resolutionTime} />
        <DetailRow label={mn.incidentSlaViolated} value={incident.slaViolated} />
        <div className="sm:col-span-2">
          <DetailRow label={mn.incidentRootCause} value={incident.rootCause} />
        </div>
      </dl>
      {SHOW_EDIT_FIELDS_BUTTON && (
        <button
          onClick={() => setEditingFields(true)}
          className="rounded border border-border px-3 py-1.5 text-sm font-medium text-text hover:bg-surface-alt"
        >
          {mn.incidentEditFields}
        </button>
      )}

      {/* Combined history: registration, field updates, severity changes, corrective actions */}
      <section>
        <h4 className="text-sm font-semibold text-text mb-2">{mn.incidentAuditTrailSection}</h4>
        <ul className="space-y-2">
          {combinedHistory.map((h) =>
            h.kind === "severity" ? (
              <li key={h.key} className="text-xs text-text-secondary">
                <span className="font-medium text-text">{mn.incidentSeverityChangedLabel}:</span> {h.actor},{" "}
                {formatDateTime(h.createdAt)}
                <div className="mt-1 flex items-center gap-2">
                  <SeverityBadge severity={h.previousSeverity} size="sm" />
                  <span className="text-muted text-sm" aria-hidden="true">
                    →
                  </span>
                  <SeverityBadge severity={h.newSeverity} size="sm" />
                </div>
                <p className="mt-1">
                  <span className="font-medium text-text-secondary">{mn.incidentDescription}:</span>{" "}
                  <span className="text-text">{h.reason}</span>
                </p>
              </li>
            ) : h.kind === "corrective_action" ? (
              <li key={h.key} className="text-xs text-text-secondary">
                <span className="font-medium text-text">{auditActionLabel("corrective_action")}</span> — {h.actor},{" "}
                {formatDateTime(h.createdAt)}
                <p className="mt-1">
                  <span className="font-medium text-text-secondary">{mn.incidentDescription}:</span>{" "}
                  <span className="text-text">{h.description}</span>
                </p>
              </li>
            ) : (
              <li key={h.key} className="text-xs text-text-secondary">
                <span className="font-medium text-text">{h.label}</span> — {h.actor}, {formatDateTime(h.createdAt)}
              </li>
            ),
          )}
        </ul>
      </section>
    </div>
  );
}
