import { mn } from "../i18n/mn";
import type { IncidentFilterValues } from "../lib/incidentFilters";

const SEVERITY_OPTIONS = ["Бага", "Дунд", "Өндөр", "Маш Өндөр"];

const inputClass = "w-full rounded border border-border px-3 py-2 text-sm";

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

  return (
    <div className="rounded-lg border border-border bg-surface p-4 sm:p-5 mb-4">
      <h2 className="text-sm font-semibold text-text mb-3">{mn.filterTitle}</h2>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <div>
          <label className="block text-sm text-text-secondary mb-1">{mn.filterSearchLabel}</label>
          <input
            className={inputClass}
            value={draft.search}
            onChange={(e) => set("search", e.target.value)}
          />
        </div>
        <div>
          <label className="block text-sm text-text-secondary mb-1">{mn.filterSeverityLabel}</label>
          <select className={inputClass} value={draft.severity} onChange={(e) => set("severity", e.target.value)}>
            <option value="">{mn.filterStatusAll}</option>
            {SEVERITY_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt}
              </option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-sm text-text-secondary mb-1">{mn.filterStatusLabel}</label>
          <select className={inputClass} value={draft.status} onChange={(e) => set("status", e.target.value)}>
            <option value="">{mn.filterStatusAll}</option>
            <option value="open">{mn.filterStatusOpen}</option>
            <option value="action_taken">{mn.filterStatusActionTaken}</option>
            <option value="closed">{mn.filterStatusClosed}</option>
          </select>
        </div>
      </div>

      <div className="mt-4 pt-3 border-t border-border flex gap-2 justify-end">
        <button
          type="button"
          onClick={onClear}
          className="rounded border border-border px-4 py-2 text-sm text-text-secondary hover:bg-surface-alt"
        >
          {mn.filterClear}
        </button>
        <button
          type="button"
          onClick={onApply}
          className="rounded bg-primary text-white px-4 py-2 text-sm font-medium hover:bg-primary-hover"
        >
          {mn.filterApply}
        </button>
      </div>
    </div>
  );
}
