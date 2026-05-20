'use client';

import * as React from 'react';
import Link from 'next/link';
import { listIncidents, type IncidentReport } from '@/lib/api';
import { SeverityBadge } from '@/components/SeverityBadge';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { formatDistanceToNow } from 'date-fns';
import { cn } from '@/lib/utils';
import { FileText, RefreshCw, ExternalLink } from 'lucide-react';

const incidentStatusColors: Record<string, string> = {
  open: 'text-red-400 border-red-800 bg-red-950/30',
  in_progress: 'text-yellow-400 border-yellow-800 bg-yellow-950/30',
  resolved: 'text-green-400 border-green-800 bg-green-950/30',
  closed: 'text-slate-400 border-slate-700 bg-slate-800/30',
};

export default function IncidentsPage() {
  const [incidents, setIncidents] = React.useState<IncidentReport[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState('');

  const fetchIncidents = React.useCallback(async () => {
    try {
      const data = await listIncidents();
      setIncidents(
        data.sort(
          (a, b) =>
            new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
        )
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load incidents');
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  return (
    <div className="container mx-auto px-4 py-6 max-w-7xl">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <FileText className="h-6 w-6 text-cyan-400" />
          <div>
            <h1 className="text-xl font-semibold font-mono">Incident Reports</h1>
            <p className="text-sm text-muted-foreground">
              All generated incident reports from the SOC pipeline
            </p>
          </div>
        </div>
        <button
          onClick={fetchIncidents}
          className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
          type="button"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {loading && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {[...Array(6)].map((_, i) => (
            <div
              key={i}
              className="rounded-lg border border-border bg-card h-48 animate-pulse"
            />
          ))}
        </div>
      )}

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-6 text-red-400 text-sm">
          {error}
        </div>
      )}

      {!loading && !error && incidents.length === 0 && (
        <div className="flex flex-col items-center justify-center h-64 gap-3 text-muted-foreground">
          <FileText className="h-12 w-12 opacity-30" />
          <p>No incident reports yet</p>
          <p className="text-xs">Reports are generated automatically after alerts are processed</p>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        {incidents.map((incident) => (
          <IncidentCard key={incident.incident_id} incident={incident} />
        ))}
      </div>
    </div>
  );
}

function IncidentCard({ incident }: { incident: IncidentReport }) {
  const createdAt = React.useMemo(() => {
    try {
      return formatDistanceToNow(new Date(incident.created_at), { addSuffix: true });
    } catch {
      return incident.created_at;
    }
  }, [incident.created_at]);

  const statusClass = incidentStatusColors[incident.status] ?? incidentStatusColors.closed;

  return (
    <Link href={`/incidents/${incident.incident_id}`} className="block group">
      <Card className="h-full transition-all hover:border-cyan-700/50 hover:shadow-lg hover:shadow-cyan-900/20 group-hover:bg-card/80">
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between gap-2">
            <CardTitle className="text-sm font-medium leading-tight line-clamp-2 group-hover:text-cyan-100 transition-colors">
              {incident.title}
            </CardTitle>
            <ExternalLink className="h-3.5 w-3.5 text-muted-foreground/40 group-hover:text-cyan-400 shrink-0 transition-colors mt-0.5" />
          </div>

          <div className="flex items-center gap-2 mt-2">
            <SeverityBadge severity={incident.severity} />
            <span
              className={cn(
                'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-mono font-semibold',
                statusClass
              )}
            >
              {incident.status.replace('_', ' ').toUpperCase()}
            </span>
          </div>
        </CardHeader>

        <CardContent className="pt-0 space-y-3">
          <p className="text-xs text-muted-foreground leading-relaxed line-clamp-3">
            {incident.executive_summary}
          </p>

          <div className="flex items-center justify-between text-xs font-mono text-muted-foreground/60">
            <span>{incident.incident_id.slice(0, 12)}...</span>
            <span>{createdAt}</span>
          </div>

          <div className="flex flex-wrap gap-1.5">
            {incident.triage && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-mono">
                Triage
              </span>
            )}
            {incident.threat_intel && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-mono">
                Threat Intel
              </span>
            )}
            {incident.investigation && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-mono">
                Investigation
              </span>
            )}
            {incident.remediation && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-mono">
                Remediation
              </span>
            )}
          </div>
        </CardContent>
      </Card>
    </Link>
  );
}
