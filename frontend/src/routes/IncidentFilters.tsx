import type { FormEvent } from "react";
import { ClearIcon, FilterIcon, SearchIcon } from "../components/incident/icons";
import { mn } from "../i18n/mn";
import type { IncidentFilterValues } from "../lib/incidentFilters";

const SEVERITY_OPTIONS = ["Маш Өндөр", "Өндөр", "Дунд", "Бага"];

const controlClass =
  "h-9 rounded-lg border border-border bg-surface px-3 text-sm text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:border-primary";

export function IncidentFilters({
  draft,
  onChange,
  onApply,
  onClear,
}: {
  draft: IncidentFilterValues;
  onChange: (next: IncidentFilterValues) => void;
  onApply: () => void;
  onClear: () => void;
}) {
  function set<K extends keyof IncidentFilterValues>(key: K, value: IncidentFilterValues[K]) {
    onChange({ ...draft, [key]: value });
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    onApply();
  }

  return (
    <form
      onSubmit={handleSubmit}
      role="search"
      className="mb-4 flex flex-wrap items-center gap-2 rounded-xl border border-border bg-surface p-3 shadow-sm"
    >
      <div className="relative min-w-0 flex-[1_1_16rem]">
        <SearchIcon size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
        <input
          type="search"
          aria-label={mn.filterSearchAria}
          placeholder={mn.filterSearchPlaceholder}
          className={`${controlClass} w-full pl-9`}
          value={draft.search}
          onChange={(e) => set("search", e.target.value)}
        />
      </div>

      <select
        aria-label={mn.filterSeverityLabel}
        className={`${controlClass} flex-[1_1_9rem] sm:flex-none sm:w-40`}
        value={draft.severity}
        onChange={(e) => set("severity", e.target.value)}
      >
        <option value="">{mn.filterSeverityAll}</option>
        {SEVERITY_OPTIONS.map((opt) => (
          <option key={opt} value={opt}>
            {opt}
          </option>
        ))}
      </select>

      <select
        aria-label={mn.filterStatusLabel}
        className={`${controlClass} flex-[1_1_9rem] sm:flex-none sm:w-52`}
        value={draft.status}
        onChange={(e) => set("status", e.target.value)}
      >
        <option value="">{mn.filterStatusAllStatuses}</option>
        <option value="open">{mn.filterStatusOpen}</option>
        <option value="action_taken">{mn.filterStatusActionTaken}</option>
        <option value="closed">{mn.filterStatusClosed}</option>
      </select>

      <select
        aria-label={mn.filterSlaLabel}
        className={`${controlClass} flex-[1_1_9rem] sm:flex-none sm:w-44`}
        value={draft.sla}
        onChange={(e) => set("sla", e.target.value)}
      >
        <option value="">{mn.filterSlaAll}</option>
        <option value="overdue">{mn.filterSlaOverdue}</option>
        <option value="within">{mn.filterSlaWithin}</option>
      </select>

      <div className="flex gap-2">
        <button
          type="button"
          onClick={onClear}
          title={mn.filterClear}
          aria-label={mn.filterClear}
          className="flex h-9 w-9 items-center justify-center rounded-lg border border-border text-text-secondary hover:bg-surface-alt hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-primary"
        >
          <ClearIcon size={16} />
        </button>
        <button
          type="submit"
          title={mn.filterApply}
          aria-label={mn.filterApply}
          className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary text-white hover:bg-primary-hover focus:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2"
        >
          <FilterIcon size={16} />
        </button>
      </div>
    </form>
  );
}
