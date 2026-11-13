import { mn } from "../../i18n/mn";
import { deadlineLabel } from "../../lib/incidentStatus";
import type { IncidentDeadline } from "../../routes/IncidentCard";
import { AlertIcon, CheckIcon, ClockIcon } from "./icons";

// Visual state is derived only from backend values: deadline.isOverdue, and the
// backend status (an open incident's countdown is still running; any other status
// means the countdown was frozen by a corrective action or manual close).
export function SlaIndicator({ deadline, status }: { deadline: IncidentDeadline; status: string }) {
  const hours = (
    <span className="text-muted font-normal">
      · {deadline.hoursAllowed}
      {mn.slaHoursSuffix}
    </span>
  );

  if (deadline.isOverdue) {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-md bg-red-50 px-2 py-1 text-xs font-medium text-red-700">
        <AlertIcon size={14} />
        {deadlineLabel(deadline.remainingSeconds, true)} {hours}
      </span>
    );
  }

  if (status === "Нээлттэй") {
    return (
      <span className="inline-flex items-center gap-1.5 rounded-md bg-surface-alt px-2 py-1 text-xs font-medium text-text-secondary ring-1 ring-inset ring-border">
        <ClockIcon size={14} />
        {deadlineLabel(deadline.remainingSeconds, false)} {hours}
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5 rounded-md bg-green-50 px-2 py-1 text-xs font-medium text-green-700">
      <CheckIcon size={14} />
      {mn.slaWithinDeadline} {hours}
    </span>
  );
}
