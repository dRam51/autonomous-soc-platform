'use client';

import * as React from 'react';
import { AlertFeed } from '@/components/AlertFeed';
import { AgentActivityPanel } from '@/components/AgentActivityPanel';
import { IncidentReportView } from '@/components/IncidentReportView';
import { SubmitAlertForm } from '@/components/SubmitAlertForm';
import { Button } from '@/components/ui/button';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from '@/components/ui/dialog';
import { Plus, Activity, FileText, Rss } from 'lucide-react';

// DashboardPage is the root layout for the SOC operator interface.
// The three-column layout mirrors a traditional SOC workstation:
//   Left column: alert queue (what needs attention)
//   Middle column: pipeline activity (what the AI is doing right now)
//   Right column: incident report (what the AI found and recommends)
export default function DashboardPage() {
  // selectedAlertId is the single source of truth for which alert all three panels
  // are showing. Lifting it to this level lets AlertFeed, AgentActivityPanel, and
  // IncidentReportView stay synchronized without prop drilling or a state manager.
  const [selectedAlertId, setSelectedAlertId] = React.useState<string | null>(null);
  const [showSubmitForm, setShowSubmitForm] = React.useState(false);

  const handleAlertSubmitted = (id: string) => {
    // Auto-select the newly submitted alert so the analyst immediately sees its
    // SSE stream and pipeline activity without having to click on it.
    setShowSubmitForm(false);
    setSelectedAlertId(id);
  };

  return (
    <div className="h-[calc(100vh-3.5rem)] flex flex-col lg:flex-row overflow-hidden">
      {/* Left column: Alert feed */}
      {/* Polls every 5 seconds and shows severity/status badges.
          Clicking a row selects the alert and activates the other two panels. */}
      <div className="w-full lg:w-1/4 flex flex-col border-b lg:border-b-0 lg:border-r border-border overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-card/50">
          <div className="flex items-center gap-2">
            <Rss className="h-4 w-4 text-cyan-400" />
            <h2 className="text-sm font-semibold font-mono">Alert Feed</h2>
          </div>
          <Button
            size="sm"
            onClick={() => setShowSubmitForm(true)}
            className="h-7 px-2 text-xs gap-1"
          >
            <Plus className="h-3.5 w-3.5" />
            New Alert
          </Button>
        </div>

        <div className="flex-1 overflow-hidden">
          <AlertFeed
            selectedAlertId={selectedAlertId}
            onSelectAlert={setSelectedAlertId}
          />
        </div>
      </div>

      {/* Middle column: Agent activity */}
      {/* Opens an SSE connection to the selected alert's event stream.
          Shows real-time pipeline progress: which agents are running,
          what tools they called, and when the HITL gate triggers. */}
      <div className="w-full lg:w-2/4 flex flex-col border-b lg:border-b-0 lg:border-r border-border overflow-hidden min-h-[300px] lg:min-h-0">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-card/50">
          <Activity className="h-4 w-4 text-cyan-400" />
          <h2 className="text-sm font-semibold font-mono">Pipeline Activity</h2>
          {selectedAlertId && (
            <span className="ml-auto font-mono text-xs text-muted-foreground/60">
              {selectedAlertId.slice(0, 8)}...
            </span>
          )}
        </div>
        <div className="flex-1 overflow-hidden">
          <AgentActivityPanel alertId={selectedAlertId} />
        </div>
      </div>

      {/* Right column: Incident report */}
      {/* Polls GET /alerts/{id}/incident until the report appears (404 while running),
          then renders tabbed views of each agent's structured output. */}
      <div className="w-full lg:w-1/4 flex flex-col overflow-hidden min-h-[300px] lg:min-h-0">
        <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-card/50">
          <FileText className="h-4 w-4 text-cyan-400" />
          <h2 className="text-sm font-semibold font-mono">Incident Report</h2>
        </div>
        <div className="flex-1 overflow-hidden">
          <IncidentReportView alertId={selectedAlertId} />
        </div>
      </div>

      {/* Alert submission dialog: opens over the dashboard without disrupting layout.
          onSuccess selects the new alert so the analyst can immediately watch the pipeline. */}
      <Dialog open={showSubmitForm} onOpenChange={setShowSubmitForm}>
        <DialogContent className="max-w-xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>Submit New Alert</DialogTitle>
            <DialogDescription>
              Ingest a security alert into the autonomous SOC pipeline.
            </DialogDescription>
          </DialogHeader>
          <SubmitAlertForm onSuccess={handleAlertSubmitted} />
        </DialogContent>
      </Dialog>
    </div>
  );
}
