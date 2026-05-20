'use client';

import * as React from 'react';
import { getIncident, type IncidentReport } from '@/lib/api';
import { Tabs, TabsList, TabsTrigger, TabsContent } from './ui/tabs';
import { Card, CardContent, CardHeader, CardTitle } from './ui/card';
import { SeverityBadge } from './SeverityBadge';
import { ScrollArea } from './ui/scroll-area';
import { cn } from '@/lib/utils';
import {
  FileText,
  Shield,
  Search,
  Globe,
  Wrench,
  Clock,
  AlertCircle,
  ChevronRight,
} from 'lucide-react';

interface IncidentReportViewProps {
  alertId: string | null;
}

export function IncidentReportView({ alertId }: IncidentReportViewProps) {
  const [report, setReport] = React.useState<IncidentReport | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState('');

  React.useEffect(() => {
    setReport(null);
    setError('');

    if (!alertId) return;

    setLoading(true);
    // stopped flag: prevents setting state after the component unmounts or alertId changes.
    // Without it, a slow API call from a previous alertId could overwrite the current report.
    let stopped = false;

    // Recursive polling: getIncident returns 404 while the pipeline is running.
    // We retry every 3 seconds until the report appears or the component unmounts.
    // In production, replace this with a one-time fetch triggered by the
    // "pipeline_complete" SSE event to eliminate unnecessary API calls.
    const poll = async () => {
      try {
        const data = await getIncident(alertId);
        if (!stopped) {
          setReport(data);
          setLoading(false);
        }
      } catch {
        if (!stopped) {
          setTimeout(poll, 3000);
        }
      }
    };

    poll();

    return () => {
      stopped = true;
      setLoading(false);
    };
  }, [alertId]);

  if (!alertId) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-muted-foreground">
        <FileText className="h-12 w-12 opacity-30" />
        <p className="text-sm">Select an alert to view incident report</p>
      </div>
    );
  }

  if (loading && !report) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-muted-foreground">
        <Clock className="h-8 w-8 animate-pulse opacity-60" />
        <p className="text-sm">Waiting for pipeline to complete...</p>
        <p className="text-xs opacity-60">Report generates automatically</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-2 text-red-400">
        <AlertCircle className="h-8 w-8" />
        <p className="text-sm">{error}</p>
      </div>
    );
  }

  if (!report) return null;

  return (
    <ScrollArea className="h-full px-2">
      <div className="py-2 space-y-3">
        <div className="flex items-start justify-between gap-2">
          <h3 className="text-sm font-semibold text-foreground leading-tight flex-1">
            {report.title}
          </h3>
          <SeverityBadge severity={report.severity} />
        </div>

        {/* Five tabs expose each agent's output separately so analysts can drill
            into the level of detail they need without scrolling through a wall of text. */}
        <Tabs defaultValue="summary">
          <TabsList className="h-auto flex-wrap gap-1 bg-muted/50">
            <TabsTrigger value="summary" className="text-xs px-2 py-1">
              <FileText className="h-3 w-3 mr-1" />
              Summary
            </TabsTrigger>
            <TabsTrigger value="triage" className="text-xs px-2 py-1">
              <Search className="h-3 w-3 mr-1" />
              Triage
            </TabsTrigger>
            <TabsTrigger value="threat" className="text-xs px-2 py-1">
              <Globe className="h-3 w-3 mr-1" />
              Threat
            </TabsTrigger>
            <TabsTrigger value="investigation" className="text-xs px-2 py-1">
              <Shield className="h-3 w-3 mr-1" />
              Invest.
            </TabsTrigger>
            <TabsTrigger value="remediation" className="text-xs px-2 py-1">
              <Wrench className="h-3 w-3 mr-1" />
              Remed.
            </TabsTrigger>
          </TabsList>

          <TabsContent value="summary">
            <SummaryTab report={report} />
          </TabsContent>
          <TabsContent value="triage">
            <TriageTab report={report} />
          </TabsContent>
          <TabsContent value="threat">
            <ThreatIntelTab report={report} />
          </TabsContent>
          <TabsContent value="investigation">
            <InvestigationTab report={report} />
          </TabsContent>
          <TabsContent value="remediation">
            <RemediationTab report={report} />
          </TabsContent>
        </Tabs>
      </div>
    </ScrollArea>
  );
}

function SummaryTab({ report }: { report: IncidentReport }) {
  const statusColors: Record<string, string> = {
    open: 'text-red-400',
    in_progress: 'text-yellow-400',
    resolved: 'text-green-400',
    closed: 'text-slate-400',
  };

  return (
    <Card className="mt-2">
      <CardContent className="pt-4 space-y-4">
        <div className="flex items-center justify-between text-xs font-mono">
          <span className="text-muted-foreground">Status</span>
          <span className={cn('font-semibold uppercase', statusColors[report.status] ?? 'text-foreground')}>
            {report.status.replace('_', ' ')}
          </span>
        </div>

        {/* Executive summary: generated by claude-haiku for non-technical audiences.
            The Reporting agent writes this in plain language, not analyst jargon. */}
        <div>
          <p className="text-xs text-muted-foreground mb-1.5">Executive Summary</p>
          <p className="text-sm leading-relaxed text-foreground/90">
            {report.executive_summary}
          </p>
        </div>

        <div className="grid grid-cols-2 gap-2 text-xs font-mono">
          <MetricCard label="Incident ID" value={report.incident_id.slice(0, 8) + '...'} />
          <MetricCard label="Severity" value={report.severity.toUpperCase()} />
        </div>

        <div className="text-xs font-mono text-muted-foreground">
          <span>Created: </span>
          <span className="text-foreground/80">
            {new Date(report.created_at).toLocaleString()}
          </span>
        </div>
      </CardContent>
    </Card>
  );
}

function TriageTab({ report }: { report: IncidentReport }) {
  const triage = report.triage;

  if (!triage) {
    return (
      <Card className="mt-2">
        <CardContent className="pt-4">
          <p className="text-sm text-muted-foreground">Triage data not available yet.</p>
        </CardContent>
      </Card>
    );
  }

  const confidencePct = Math.round(triage.confidence * 100);

  return (
    <Card className="mt-2">
      <CardContent className="pt-4 space-y-4">
        {/* Confidence bar: visual representation of the triage agent's stated certainty.
            Confidence calibration (in calibration.py) tracks whether this value is reliable. */}
        <div className="space-y-1.5">
          <div className="flex justify-between text-xs font-mono">
            <span className="text-muted-foreground">Confidence</span>
            <span className="text-cyan-400">{confidencePct}%</span>
          </div>
          <div className="h-2 rounded-full bg-muted overflow-hidden">
            <div
              className="h-full rounded-full bg-gradient-to-r from-cyan-600 to-cyan-400 transition-all"
              style={{ width: `${confidencePct}%` }}
            />
          </div>
        </div>

        <div className="text-xs font-mono flex justify-between">
          <span className="text-muted-foreground">Severity</span>
          <SeverityBadge severity={triage.severity} />
        </div>

        <div>
          <p className="text-xs text-muted-foreground mb-1">Reasoning</p>
          {/* Reasoning includes vote distribution and self-reflection critique notes
              appended by the triage agent, making the pipeline's decisions auditable. */}
          <p className="text-sm leading-relaxed text-foreground/90">{triage.reasoning}</p>
        </div>

        <div>
          <p className="text-xs text-muted-foreground mb-1">Recommended Action</p>
          <p className="text-sm font-medium text-cyan-300">{triage.recommended_action}</p>
        </div>

        {triage.mitre_techniques.length > 0 && (
          <div>
            <p className="text-xs text-muted-foreground mb-2">MITRE Techniques</p>
            <div className="flex flex-wrap gap-1.5">
              {triage.mitre_techniques.map((tech) => (
                <span
                  key={tech}
                  className="font-mono text-xs px-2 py-0.5 rounded border border-blue-800 bg-blue-950 text-blue-300"
                >
                  {tech}
                </span>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function ThreatIntelTab({ report }: { report: IncidentReport }) {
  const intel = report.threat_intel;

  if (!intel) {
    return (
      <Card className="mt-2">
        <CardContent className="pt-4">
          <p className="text-sm text-muted-foreground">Threat intel not available yet.</p>
        </CardContent>
      </Card>
    );
  }

  const riskPct = (intel.risk_score / 10) * 100;
  // Color coding mirrors CVSS: 8+ is critical/red, 6-8 is high/orange, 4-6 is medium/yellow.
  const riskColor =
    intel.risk_score >= 8
      ? 'text-red-400'
      : intel.risk_score >= 6
      ? 'text-orange-400'
      : intel.risk_score >= 4
      ? 'text-yellow-400'
      : 'text-green-400';

  return (
    <Card className="mt-2">
      <CardContent className="pt-4 space-y-4">
        <div className="flex items-center gap-4">
          <div className="flex-1">
            <div className="flex justify-between text-xs font-mono mb-1.5">
              <span className="text-muted-foreground">Risk Score</span>
              <span className={cn('font-bold text-base', riskColor)}>
                {intel.risk_score.toFixed(1)}/10
              </span>
            </div>
            <div className="h-3 rounded-full bg-muted overflow-hidden">
              <div
                className={cn(
                  'h-full rounded-full transition-all',
                  intel.risk_score >= 8
                    ? 'bg-red-600'
                    : intel.risk_score >= 6
                    ? 'bg-orange-600'
                    : intel.risk_score >= 4
                    ? 'bg-yellow-600'
                    : 'bg-green-600'
                )}
                style={{ width: `${riskPct}%` }}
              />
            </div>
          </div>
        </div>

        {intel.related_cves.length > 0 && (
          <div>
            <p className="text-xs text-muted-foreground mb-2">Related CVEs</p>
            <div className="flex flex-wrap gap-1.5">
              {intel.related_cves.map((cve) => (
                <span
                  key={cve}
                  className="font-mono text-xs px-2 py-0.5 rounded border border-red-800 bg-red-950 text-red-300"
                >
                  {cve}
                </span>
              ))}
            </div>
          </div>
        )}

        {intel.mitre_tactics.length > 0 && (
          <div>
            <p className="text-xs text-muted-foreground mb-2">MITRE Tactics</p>
            <div className="flex flex-wrap gap-1.5">
              {intel.mitre_tactics.map((tac) => (
                <span
                  key={tac}
                  className="font-mono text-xs px-2 py-0.5 rounded border border-purple-800 bg-purple-950 text-purple-300"
                >
                  {tac}
                </span>
              ))}
            </div>
          </div>
        )}

        {intel.threat_actors.length > 0 && (
          <div>
            <p className="text-xs text-muted-foreground mb-2">Threat Actors</p>
            <div className="flex flex-wrap gap-1.5">
              {intel.threat_actors.map((actor) => (
                <span
                  key={actor}
                  className="font-mono text-xs px-2 py-0.5 rounded border border-orange-800 bg-orange-950 text-orange-300"
                >
                  {actor}
                </span>
              ))}
            </div>
          </div>
        )}

        <div>
          <p className="text-xs text-muted-foreground mb-1">IOC Analysis</p>
          <p className="text-sm leading-relaxed text-foreground/90">{intel.ioc_analysis}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function InvestigationTab({ report }: { report: IncidentReport }) {
  const inv = report.investigation;

  if (!inv) {
    return (
      <Card className="mt-2">
        <CardContent className="pt-4">
          {/* Investigation is absent for low/info severity alerts: supervisor routing
              skips the investigation node to save cost and time for low-risk events. */}
          <p className="text-sm text-muted-foreground">Investigation data not available yet.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="mt-2">
      <CardContent className="pt-4 space-y-4">
        {/* Binary risk flags are the highest-priority signals from investigation.
            Lateral movement or exfil risk immediately changes the response priority. */}
        <div className="grid grid-cols-2 gap-2">
          <RiskFlag
            label="Lateral Movement"
            active={inv.lateral_movement_detected}
            activeColor="text-red-400"
          />
          <RiskFlag
            label="Data Exfil Risk"
            active={inv.data_exfiltration_risk}
            activeColor="text-orange-400"
          />
        </div>

        <div>
          <p className="text-xs text-muted-foreground mb-1">Attack Chain</p>
          {/* Attack chain is the narrative reconstruction of the attack progression,
              generated by the investigation agent using extended thinking. */}
          <p className="text-sm leading-relaxed text-foreground/90">{inv.attack_chain}</p>
        </div>

        {inv.affected_assets.length > 0 && (
          <div>
            <p className="text-xs text-muted-foreground mb-2">Affected Assets</p>
            <div className="space-y-1">
              {inv.affected_assets.map((asset) => (
                <div key={asset} className="flex items-center gap-2 text-xs font-mono">
                  <ChevronRight className="h-3 w-3 text-cyan-500 shrink-0" />
                  <span className="text-foreground/80">{asset}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {inv.timeline.length > 0 && (
          <div>
            <p className="text-xs text-muted-foreground mb-2">
              Timeline ({inv.timeline.length} events)
            </p>
            <div className="space-y-1.5 max-h-40 overflow-y-auto pr-1">
              {inv.timeline.map((item, idx) => (
                <div
                  key={idx}
                  className="text-xs font-mono p-2 rounded border border-border bg-muted/20 text-foreground/70"
                >
                  {JSON.stringify(item)}
                </div>
              ))}
            </div>
          </div>
        )}

        <div>
          <p className="text-xs text-muted-foreground mb-1">Full Analysis</p>
          <p className="text-sm leading-relaxed text-foreground/90 max-h-32 overflow-y-auto">
            {inv.full_analysis}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}

function RemediationTab({ report }: { report: IncidentReport }) {
  const rem = report.remediation;

  if (!rem) {
    return (
      <Card className="mt-2">
        <CardContent className="pt-4">
          <p className="text-sm text-muted-foreground">Remediation plan not available yet.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="mt-2">
      <CardContent className="pt-4 space-y-4">
        <div className="flex justify-between text-xs font-mono">
          <span className="text-muted-foreground">Estimated Effort</span>
          <span className="text-cyan-400">{rem.estimated_effort}</span>
        </div>

        {rem.playbook_reference && (
          <div className="text-xs font-mono">
            <span className="text-muted-foreground">Playbook: </span>
            <span className="text-blue-400">{rem.playbook_reference}</span>
          </div>
        )}

        {/* Color coding aligns with NIST IR urgency: red = do now, yellow = soon, green = eventually */}
        <ActionList
          title="Immediate Actions"
          items={rem.immediate_actions}
          colorClass="border-red-800 bg-red-950/30 text-red-300"
          dotColor="bg-red-500"
        />

        <ActionList
          title="Short-term Actions"
          items={rem.short_term_actions}
          colorClass="border-yellow-800 bg-yellow-950/30 text-yellow-300"
          dotColor="bg-yellow-500"
        />

        <ActionList
          title="Long-term Recommendations"
          items={rem.long_term_recommendations}
          colorClass="border-green-800 bg-green-950/30 text-green-300"
          dotColor="bg-green-500"
        />
      </CardContent>
    </Card>
  );
}

// ---- Helper Sub-Components ----

function MetricCard({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded border border-border bg-muted/30 p-2">
      <p className="text-muted-foreground text-xs mb-0.5">{label}</p>
      <p className="text-foreground font-semibold text-xs">{value}</p>
    </div>
  );
}

// RiskFlag renders a binary indicator (YES/NO) with color emphasis when active.
// A red YES for lateral movement is more immediately alarming than plain text.
function RiskFlag({
  label,
  active,
  activeColor,
}: {
  label: string;
  active: boolean;
  activeColor: string;
}) {
  return (
    <div
      className={cn(
        'rounded border p-2 text-xs font-mono text-center',
        active
          ? cn('border-current', activeColor)
          : 'border-border text-muted-foreground'
      )}
    >
      <div
        className={cn(
          'h-2 w-2 rounded-full mx-auto mb-1',
          active ? 'bg-current' : 'bg-muted'
        )}
      />
      {label}
      <br />
      <span className="font-bold">{active ? 'YES' : 'NO'}</span>
    </div>
  );
}

function ActionList({
  title,
  items,
  colorClass,
  dotColor,
}: {
  title: string;
  items: string[];
  colorClass: string;
  dotColor: string;
}) {
  if (items.length === 0) return null;

  return (
    <div>
      <p className="text-xs text-muted-foreground mb-2">{title}</p>
      <div className={cn('rounded border p-3 space-y-1.5', colorClass)}>
        {items.map((item, idx) => (
          <div key={idx} className="flex items-start gap-2 text-xs">
            <div className={cn('h-1.5 w-1.5 rounded-full mt-1.5 shrink-0', dotColor)} />
            <span className="leading-relaxed">{item}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
