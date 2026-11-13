import { useMemo, useState, type ReactNode } from "react";
import { useMutation, useQuery } from "@apollo/client/react";
import { AlertIcon, BackIcon, ClockIcon, InboxIcon, PlusIcon, ShieldIcon } from "../components/incident/icons";
import { KpiCard, KpiCardSkeleton } from "../components/incident/KpiCard";
import { DELETE_INCIDENT, GET_INCIDENT_ACCESS, GET_INCIDENTS } from "../graphql/operations/incidents";
import { mn } from "../i18n/mn";
import {
  EMPTY_INCIDENT_FILTERS,
  filterIncidents,
  hasActiveFilters,
  type IncidentFilterValues,
} from "../lib/incidentFilters";
import { IncidentCard, IncidentCardSkeleton, type Incident } from "./IncidentCard";
import { IncidentFilters } from "./IncidentFilters";
import { IncidentForm } from "./IncidentForm";

type QueryResult = {
  incidents: { totalCount: number; items: Incident[] };
};

type AccessResult = {
  incidentAccess: { canView: boolean; canManage: boolean };
};

// Each KPI maps onto an existing filter value, so clicking a card is just a filter preset.
type KpiKey = "total" | "new" | "overdue" | "veryHigh";

const KPI_PRESETS: Record<KpiKey, IncidentFilterValues> = {
  total: EMPTY_INCIDENT_FILTERS,
  new: { ...EMPTY_INCIDENT_FILTERS, status: "open" },
  overdue: { ...EMPTY_INCIDENT_FILTERS, sla: "overdue" },
  veryHigh: { ...EMPTY_INCIDENT_FILTERS, severity: "Маш Өндөр" },
};

function sameFilters(a: IncidentFilterValues, b: IncidentFilterValues): boolean {
  return a.search === b.search && a.severity === b.severity && a.status === b.status && a.sla === b.sla;
}

export function IncidentRegisterPage() {
  const [createFormOpen, setCreateFormOpen] = useState(false);
  const [draftFilters, setDraftFilters] = useState<IncidentFilterValues>(EMPTY_INCIDENT_FILTERS);
  const [appliedFilters, setAppliedFilters] = useState<IncidentFilterValues>(EMPTY_INCIDENT_FILTERS);

  const { data: accessData, loading: accessLoading } = useQuery<AccessResult>(GET_INCIDENT_ACCESS);
  const canView = accessData?.incidentAccess.canView ?? false;
  const canManage = accessData?.incidentAccess.canManage ?? false;
  const noAccess = !!accessData && !canView;
  const { data, loading: incidentsLoading, error, refetch } = useQuery<QueryResult>(GET_INCIDENTS, { skip: !canView });
  const loading = accessLoading || incidentsLoading;
  const [deleteIncident] = useMutation(DELETE_INCIDENT);

  const allItems = useMemo(() => data?.incidents.items ?? [], [data]);
  const filteredItems = useMemo(() => filterIncidents(allItems, appliedFilters), [allItems, appliedFilters]);

  const counts = useMemo(
    () => ({
      total: allItems.length,
      new: filterIncidents(allItems, KPI_PRESETS.new).length,
      overdue: filterIncidents(allItems, KPI_PRESETS.overdue).length,
      veryHigh: filterIncidents(allItems, KPI_PRESETS.veryHigh).length,
    }),
    [allItems],
  );

  async function handleDelete(incident: Incident) {
    if (!window.confirm(mn.incidentDeleteConfirm)) return;
    await deleteIncident({ variables: { id: incident.id } });
    await refetch();
  }

  function handleApplyFilters() {
    setAppliedFilters(draftFilters);
  }

  function handleClearFilters() {
    setDraftFilters(EMPTY_INCIDENT_FILTERS);
    setAppliedFilters(EMPTY_INCIDENT_FILTERS);
  }

  function handleKpiClick(key: KpiKey) {
    const preset = KPI_PRESETS[key];
    const next = sameFilters(appliedFilters, preset) ? EMPTY_INCIDENT_FILTERS : preset;
    setDraftFilters(next);
    setAppliedFilters(next);
  }

  const kpis: { key: KpiKey; label: string; hint: string; icon: ReactNode; tone: "primary" | "info" | "danger" | "severe" }[] = [
    { key: "total", label: mn.kpiTotal, hint: mn.kpiTotalHint, icon: <ShieldIcon size={18} />, tone: "primary" },
    { key: "new", label: mn.kpiNew, hint: mn.kpiNewHint, icon: <InboxIcon size={18} />, tone: "info" },
    { key: "overdue", label: mn.kpiOverdue, hint: mn.kpiOverdueHint, icon: <ClockIcon size={18} />, tone: "danger" },
    { key: "veryHigh", label: mn.kpiVeryHigh, hint: mn.kpiVeryHighHint, icon: <AlertIcon size={18} />, tone: "severe" },
  ];

  const showSkeleton = loading && !data;
  const showError = !!error && !data;

  return (
    <div className="w-full px-4 py-4 sm:px-6 sm:py-6 lg:px-10">
      {/* Header */}
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 items-start gap-2">
          <button
            type="button"
            onClick={() => window.history.back()}
            title={mn.back}
            aria-label={mn.back}
            className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg text-text-secondary hover:bg-surface hover:text-text focus:outline-none focus-visible:ring-2 focus-visible:ring-primary"
          >
            <BackIcon size={18} />
          </button>
          <div className="min-w-0">
            <h1 className="text-xl font-semibold leading-tight text-text">{mn.incidentRegisterTitle}</h1>
            <p className="mt-0.5 text-sm text-muted">{mn.incidentRegisterSubtitle}</p>
          </div>
        </div>
        {data && !createFormOpen && !canManage && (
          <span className="inline-flex h-8 items-center rounded-full border border-border bg-surface px-3 text-xs font-medium text-text-secondary">
            {mn.incidentReadOnly}
          </span>
        )}
        {data && !createFormOpen && canManage && (
          <button
            type="button"
            onClick={() => setCreateFormOpen(true)}
            className="inline-flex h-10 items-center gap-1.5 rounded-lg bg-primary px-4 text-sm font-medium text-white shadow-sm hover:bg-primary-hover focus:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-2"
          >
            <PlusIcon size={16} />
            {mn.newIncident}
          </button>
        )}
      </div>

      {showSkeleton && (
        <div aria-busy="true" aria-label={mn.loading}>
          <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
            {[0, 1, 2, 3].map((i) => (
              <KpiCardSkeleton key={i} />
            ))}
          </div>
          <div className="mb-4 h-[60px] rounded-xl border border-border bg-surface shadow-sm animate-pulse" />
          <div className="space-y-3">
            {[0, 1, 2].map((i) => (
              <IncidentCardSkeleton key={i} />
            ))}
          </div>
          <span className="sr-only">{mn.loading}</span>
        </div>
      )}

      {noAccess && (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-xl border border-border bg-surface p-4 text-sm text-text-secondary shadow-sm"
        >
          <ShieldIcon size={18} className="mt-0.5 text-muted" />
          <p>{mn.incidentNoAccess}</p>
        </div>
      )}

      {showError && (
        <div
          role="alert"
          className="flex flex-col items-start gap-3 rounded-xl border border-danger-border bg-danger-light p-4 sm:flex-row sm:items-center sm:justify-between"
        >
          <div className="flex items-start gap-2 text-danger">
            <AlertIcon size={18} className="mt-0.5" />
            <div>
              <p className="text-sm font-medium">{mn.incidentLoadError}</p>
              <p className="mt-0.5 text-xs text-text-secondary break-words">
                {mn.error}: {error.message}
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={() => void refetch()}
            className="h-9 rounded-lg border border-danger-border bg-surface px-4 text-sm font-medium text-danger hover:bg-danger-light focus:outline-none focus-visible:ring-2 focus-visible:ring-danger"
          >
            {mn.retry}
          </button>
        </div>
      )}

      {data && (
        <>
          {createFormOpen && canManage && (
            <IncidentForm
              incident={null}
              onSaved={() => {
                setCreateFormOpen(false);
                void refetch();
              }}
              onCancel={() => setCreateFormOpen(false)}
            />
          )}

          {!createFormOpen && (
            <>
              <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
                {kpis.map((k) => (
                  <KpiCard
                    key={k.key}
                    label={k.label}
                    value={counts[k.key]}
                    hint={k.hint}
                    icon={k.icon}
                    tone={k.tone}
                    active={k.key !== "total" && sameFilters(appliedFilters, KPI_PRESETS[k.key])}
                    onClick={() => handleKpiClick(k.key)}
                  />
                ))}
              </div>

              <IncidentFilters
                draft={draftFilters}
                onChange={setDraftFilters}
                onApply={handleApplyFilters}
                onClear={handleClearFilters}
              />

              <p className="mb-3 text-xs text-muted" aria-live="polite">
                {hasActiveFilters(appliedFilters)
                  ? `${filteredItems.length} ${mn.incidentOf} ${allItems.length} ${mn.incidentResultCount}`
                  : `${mn.total}: ${allItems.length} ${mn.incidentResultCount}`}
              </p>

              {filteredItems.length === 0 ? (
                <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed border-border-strong bg-surface px-4 py-10 text-center">
                  <span className="flex h-10 w-10 items-center justify-center rounded-full bg-surface-alt text-muted">
                    <InboxIcon size={20} />
                  </span>
                  <p className="text-sm text-text-secondary">
                    {allItems.length === 0 ? mn.incidentEmptyAll : mn.incidentFilterNoMatch}
                  </p>
                  {allItems.length > 0 && (
                    <button
                      type="button"
                      onClick={handleClearFilters}
                      className="mt-1 rounded text-sm font-medium text-primary hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                    >
                      {mn.filterClear}
                    </button>
                  )}
                </div>
              ) : (
                <div className="space-y-3">
                  {filteredItems.map((incident) => (
                    <IncidentCard
                      key={incident.id}
                      incident={incident}
                      onDelete={handleDelete}
                      onChanged={() => void refetch()}
                      canManage={canManage}
                    />
                  ))}
                </div>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}
