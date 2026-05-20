'use client';

import * as React from 'react';
import { formatDistanceToNow } from 'date-fns';
import { listAlerts, type AlertResponse } from '@/lib/api';
import { SeverityBadge } from './SeverityBadge';
import { StatusBadge } from './StatusBadge';
import { cn } from '@/lib/utils';
import { RefreshCw, Inbox } from 'lucide-react';

interface AlertFeedProps {
  selectedAlertId: string | null;
  onSelectAlert: (id: string) => void;
}

// Skeleton placeholder shown while the initial fetch is in progress.
// Using a skeleton instead of a spinner gives the UI a content-shaped loading state
// that reduces perceived loading time (it looks like content is almost ready).
function AlertRowSkeleton() {
  return (
    <div className="flex flex-col gap-2 p-3 border-b border-border animate-pulse">
      <div className="h-3.5 bg-muted rounded w-3/4" />
      <div className="flex gap-2">
        <div className="h-3 bg-muted rounded w-16" />
        <div className="h-3 bg-muted rounded w-16" />
      </div>
      <div className="h-3 bg-muted rounded w-1/3" />
    </div>
  );
}

export function AlertFeed({ selectedAlertId, onSelectAlert }: AlertFeedProps) {
  const [alerts, setAlerts] = React.useState<AlertResponse[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [lastRefresh, setLastRefresh] = React.useState<Date>(new Date());

  // useCallback memoizes fetchAlerts so it is stable across renders and can be
  // used safely as a dependency in the useEffect without triggering infinite loops.
  const fetchAlerts = React.useCallback(async () => {
    try {
      const data = await listAlerts();
      // Sort newest-first so the most recently submitted alert is at the top.
      setAlerts(data.sort((a, b) =>
        new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      ));
      setLastRefresh(new Date());
    } catch {
      // Silently fail on background refresh so the UI does not flicker with
      // error states during normal polling. A persistent failure would be
      // detected eventually by the user noticing the feed is not updating.
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    fetchAlerts();
    // Poll every 5 seconds so newly submitted alerts and status changes (triaging,
    // closed) appear without requiring the analyst to manually refresh. 5s is short
    // enough to feel responsive but not so aggressive that it generates excessive
    // API traffic. In production, replace this with a WebSocket subscription.
    const interval = setInterval(fetchAlerts, 5000);
    return () => clearInterval(interval);
  }, [fetchAlerts]);

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center justify-between px-3 py-2 border-b border-border">
        <span className="text-xs text-muted-foreground font-mono">
          {alerts.length} alert{alerts.length !== 1 ? 's' : ''}
        </span>
        <button
          onClick={fetchAlerts}
          className="text-muted-foreground hover:text-foreground transition-colors"
          title="Refresh"
          type="button"
        >
          <RefreshCw className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        {loading ? (
          <>
            <AlertRowSkeleton />
            <AlertRowSkeleton />
            <AlertRowSkeleton />
            <AlertRowSkeleton />
          </>
        ) : alerts.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 gap-2 text-muted-foreground">
            <Inbox className="h-8 w-8 opacity-40" />
            <p className="text-sm">No alerts yet</p>
          </div>
        ) : (
          alerts.map((alert) => (
            <AlertRow
              key={alert.id}
              alert={alert}
              isSelected={selectedAlertId === alert.id}
              onSelect={() => onSelectAlert(alert.id)}
            />
          ))
        )}
      </div>

      <div className="px-3 py-1.5 border-t border-border">
        <p className="text-xs text-muted-foreground/60 font-mono">
          Updated {formatDistanceToNow(lastRefresh, { addSuffix: true })}
        </p>
      </div>
    </div>
  );
}

interface AlertRowProps {
  alert: AlertResponse;
  isSelected: boolean;
  onSelect: () => void;
}

function AlertRow({ alert, isSelected, onSelect }: AlertRowProps) {
  // useMemo prevents re-computing the relative timestamp on every parent render.
  // alert.created_at is stable for any given alert, so this only recomputes
  // if the alert object changes (which only happens on severity/status updates).
  const createdAt = React.useMemo(() => {
    try {
      return formatDistanceToNow(new Date(alert.created_at), { addSuffix: true });
    } catch {
      return alert.created_at;
    }
  }, [alert.created_at]);

  return (
    <button
      type="button"
      onClick={onSelect}
      className={cn(
        'w-full text-left flex flex-col gap-1.5 p-3 border-b border-border transition-colors',
        'hover:bg-slate-800/60',
        // Left border accent provides a clear visual indicator for the selected row
        // without requiring a background that might obscure severity badge colors.
        isSelected
          ? 'bg-cyan-950/40 border-l-2 border-l-cyan-500'
          : 'border-l-2 border-l-transparent'
      )}
    >
      <p
        className={cn(
          'text-sm font-medium leading-tight line-clamp-2',
          isSelected ? 'text-cyan-100' : 'text-foreground'
        )}
      >
        {alert.title}
      </p>

      <div className="flex flex-wrap items-center gap-1.5">
        <span className="text-xs font-mono text-muted-foreground bg-muted px-1.5 py-0.5 rounded">
          {alert.source}
        </span>
        {/* SeverityBadge is absent (returns null) while severity is undefined,
            which is the case before triage completes. */}
        <SeverityBadge severity={alert.severity} />
        <StatusBadge status={alert.status} />
      </div>

      <div className="flex items-center justify-between">
        <span className="text-xs text-muted-foreground font-mono">{createdAt}</span>
        {alert.source_ip && (
          <span className="text-xs font-mono text-cyan-600/80">
            {alert.source_ip}
          </span>
        )}
      </div>
    </button>
  );
}
