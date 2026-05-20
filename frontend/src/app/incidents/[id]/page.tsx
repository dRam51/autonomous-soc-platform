'use client';

import * as React from 'react';
import { useParams, useRouter } from 'next/navigation';
import { getIncidentById } from '@/lib/api';
import { IncidentReportView } from '@/components/IncidentReportView';
import { Button } from '@/components/ui/button';
import { ArrowLeft, Shield } from 'lucide-react';

export default function IncidentDetailPage() {
  const params = useParams();
  const router = useRouter();
  const incidentId = typeof params.id === 'string' ? params.id : '';

  const [alertId, setAlertId] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState('');
  const [incidentTitle, setIncidentTitle] = React.useState('');

  React.useEffect(() => {
    if (!incidentId) return;

    const load = async () => {
      try {
        const incident = await getIncidentById(incidentId);
        setAlertId(incident.alert_id);
        setIncidentTitle(incident.title);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load incident');
      } finally {
        setLoading(false);
      }
    };

    load();
  }, [incidentId]);

  return (
    <div className="min-h-[calc(100vh-3.5rem)] flex flex-col">
      <div className="border-b border-border bg-card/50 px-4 py-3">
        <div className="flex items-center gap-3 max-w-7xl mx-auto">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => router.push('/incidents')}
            className="gap-2 text-muted-foreground hover:text-foreground"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to Incidents
          </Button>

          <div className="flex items-center gap-2 ml-2">
            <Shield className="h-4 w-4 text-cyan-400" />
            <h1 className="text-sm font-semibold font-mono truncate max-w-xl">
              {incidentTitle || incidentId}
            </h1>
          </div>
        </div>
      </div>

      <div className="flex-1 max-w-3xl mx-auto w-full px-4 py-6">
        {loading && (
          <div className="flex items-center justify-center h-64 text-muted-foreground">
            <div className="flex flex-col items-center gap-3">
              <div className="h-8 w-8 border-2 border-cyan-400 border-t-transparent rounded-full animate-spin" />
              <p className="text-sm">Loading incident...</p>
            </div>
          </div>
        )}

        {error && (
          <div className="rounded-lg border border-red-800 bg-red-950/30 p-6 text-red-400 text-sm">
            {error}
          </div>
        )}

        {!loading && !error && alertId && (
          <div className="h-[calc(100vh-12rem)]">
            <IncidentReportView alertId={alertId} />
          </div>
        )}
      </div>
    </div>
  );
}
