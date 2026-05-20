'use client';

import * as React from 'react';
import { formatDistanceToNow } from 'date-fns';
import {
  Clock,
  Cpu,
  CheckCircle,
  Copy,
  XCircle,
  Shield,
  AlertTriangle,
  CheckCheck,
  Activity,
} from 'lucide-react';
import { streamAlertEvents, approveAlert, getAlert, type SSEEvent, type SSEEventType } from '@/lib/api';
import { Button } from './ui/button';
import { ScrollArea } from './ui/scroll-area';
import { cn } from '@/lib/utils';

// Maps each SSE event type to a display icon and color. Adding a new event type from
// the backend only requires adding an entry here; the rendering logic is generic.
const EVENT_CONFIG: Record<
  SSEEventType,
  { Icon: React.ElementType; color: string; label: string }
> = {
  pipeline_queued: { Icon: Clock, color: 'text-cyan-400', label: 'Pipeline Queued' },
  agent_started: { Icon: Cpu, color: 'text-blue-400', label: 'Agent Started' },
  agent_completed: { Icon: CheckCircle, color: 'text-green-400', label: 'Agent Completed' },
  duplicate_detected: { Icon: Copy, color: 'text-yellow-400', label: 'Duplicate Detected' },
  auto_closed: { Icon: XCircle, color: 'text-slate-400', label: 'Auto Closed' },
  pipeline_complete: { Icon: Shield, color: 'text-cyan-400', label: 'Pipeline Complete' },
  pipeline_error: { Icon: AlertTriangle, color: 'text-red-400', label: 'Pipeline Error' },
  stream_end: { Icon: CheckCheck, color: 'text-green-500', label: 'Stream End' },
};

// Extend SSEEvent with a locally generated ID for React list keys.
// We cannot use event timestamp as a key because two events in the same millisecond
// would have the same key, causing React reconciliation bugs.
interface ActivityEvent extends SSEEvent {
  localId: string;
}

interface AgentActivityPanelProps {
  alertId: string | null;
}

export function AgentActivityPanel({ alertId }: AgentActivityPanelProps) {
  const [events, setEvents] = React.useState<ActivityEvent[]>([]);
  const [connected, setConnected] = React.useState(false);
  const [pipelineDone, setPipelineDone] = React.useState(false);
  // HITL UI state: showApprove appears when the pipeline pauses at the HITL gate.
  const [showApprove, setShowApprove] = React.useState(false);
  const [approving, setApproving] = React.useState(false);
  const [approveError, setApproveError] = React.useState('');
  const bottomRef = React.useRef<HTMLDivElement>(null);
  const hitlTimerRef = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  React.useEffect(() => {
    // Reset all state when alertId changes so stale events from the previous alert
    // do not bleed into the new alert's activity stream.
    setEvents([]);
    setConnected(false);
    setPipelineDone(false);
    setShowApprove(false);
    setApproveError('');

    if (!alertId) return;

    setConnected(true);

    // streamAlertEvents opens an EventSource connection. It returns a cleanup
    // function that closes the connection when the component unmounts or alertId changes.
    const cleanup = streamAlertEvents(alertId, (event) => {
      const activityEvent: ActivityEvent = {
        ...event,
        localId: `${event.ts}-${Math.random()}`,
      };

      setEvents((prev) => [...prev, activityEvent]);

      // Terminal events: mark pipeline as done and clear the HITL approval prompt.
      if (event.event === 'pipeline_complete' || event.event === 'stream_end') {
        setPipelineDone(true);
        setShowApprove(false);
        if (hitlTimerRef.current) clearTimeout(hitlTimerRef.current);
      }

      if (event.event === 'pipeline_error') {
        setPipelineDone(true);
      }
    });

    // HITL detection heuristic: if the alert is still "triaging" after 10 seconds,
    // it is likely paused at the HITL gate (NodeInterrupt in LangGraph). We cannot
    // receive an SSE event for the pause itself because the pipeline is frozen server-side.
    // Polling the alert status after a delay is the simplest way to detect it from the client.
    hitlTimerRef.current = setTimeout(async () => {
      if (!pipelineDone) {
        try {
          const alert = await getAlert(alertId);
          if (alert.status === 'triaging') {
            setShowApprove(true);
          }
        } catch {
          // Ignore: if the API call fails, the analyst can still submit via other means.
        }
      }
    }, 10000);

    return () => {
      cleanup();
      setConnected(false);
      if (hitlTimerRef.current) clearTimeout(hitlTimerRef.current);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [alertId]);

  // Auto-scroll to the latest event as new ones arrive, similar to a live log tail.
  React.useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [events]);

  const handleApprove = async () => {
    if (!alertId) return;
    setApproving(true);
    setApproveError('');
    try {
      // approveAlert() calls POST /alerts/{id}/approve which resumes the
      // LangGraph pipeline from the hitl_gate node with hitl_approved=True.
      await approveAlert(alertId);
      setShowApprove(false);
    } catch (err) {
      setApproveError(err instanceof Error ? err.message : 'Failed to approve');
    } finally {
      setApproving(false);
    }
  };

  if (!alertId) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-muted-foreground">
        <Activity className="h-12 w-12 opacity-30" />
        <p className="text-sm">Select an alert to see pipeline activity</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      {/* Connection status indicator: pulses while pipeline is running, goes green on completion */}
      <div className="flex items-center gap-2 px-4 py-3 border-b border-border">
        <div
          className={cn(
            'h-2 w-2 rounded-full',
            connected && !pipelineDone
              ? 'bg-cyan-400 animate-pulse'
              : pipelineDone
              ? 'bg-green-400'
              : 'bg-slate-600'
          )}
        />
        <span className="text-xs font-mono text-muted-foreground">
          {connected && !pipelineDone
            ? 'Pipeline running...'
            : pipelineDone
            ? 'Pipeline complete'
            : 'Connecting...'}
        </span>
        <span className="ml-auto text-xs font-mono text-muted-foreground/60">
          {events.length} event{events.length !== 1 ? 's' : ''}
        </span>
      </div>

      <ScrollArea className="flex-1 px-4 py-3">
        {events.length === 0 && (
          <div className="flex flex-col items-center justify-center h-24 gap-2 text-muted-foreground">
            <Clock className="h-6 w-6 opacity-40 animate-pulse" />
            <p className="text-xs">Waiting for events...</p>
          </div>
        )}

        {/* Timeline: vertical line connecting events, newest at bottom */}
        <div className="relative">
          {events.length > 0 && (
            <div className="absolute left-[11px] top-3 bottom-3 w-px bg-border" />
          )}

          <div className="space-y-1">
            {events.map((event, idx) => (
              <EventItem key={event.localId} event={event} isLast={idx === events.length - 1} />
            ))}
          </div>
        </div>
        <div ref={bottomRef} />
      </ScrollArea>

      {/* HITL approval prompt: shown when the pipeline is paused on a CRITICAL alert.
          The amber color conveys urgency without alarming the analyst unnecessarily. */}
      {showApprove && (
        <div className="px-4 py-3 border-t border-border bg-amber-950/30">
          <p className="text-xs text-amber-400 mb-2 font-mono">
            CRITICAL alert requires human approval to continue investigation.
          </p>
          {approveError && (
            <p className="text-xs text-red-400 mb-2">{approveError}</p>
          )}
          <Button
            onClick={handleApprove}
            disabled={approving}
            size="sm"
            className="w-full bg-amber-600 hover:bg-amber-500 text-white"
          >
            <Shield className="mr-2 h-3.5 w-3.5" />
            {approving ? 'Approving...' : 'Approve Investigation'}
          </Button>
        </div>
      )}
    </div>
  );
}

interface EventItemProps {
  event: ActivityEvent;
  isLast: boolean;
}

function EventItem({ event, isLast }: EventItemProps) {
  const config = EVENT_CONFIG[event.event] ?? {
    Icon: Activity,
    color: 'text-slate-400',
    label: event.event,
  };
  const { Icon } = config;

  // useMemo prevents re-computing the relative timestamp on every render.
  // The timestamp only changes if event.ts changes, which it never does.
  const timestamp = React.useMemo(() => {
    try {
      return formatDistanceToNow(new Date(event.ts), { addSuffix: true });
    } catch {
      return event.ts;
    }
  }, [event.ts]);

  // Exclude alert_id from the displayed data keys to reduce noise;
  // the alert ID is already shown in the header bar.
  const dataKeys = Object.keys(event.data ?? {}).filter(
    (k) => k !== 'alert_id'
  );

  return (
    <div className="flex gap-3 py-2">
      <div className="flex flex-col items-center">
        {/* Highlight the last (most recent) event with a distinct border to draw the eye */}
        <div
          className={cn(
            'flex h-6 w-6 shrink-0 items-center justify-center rounded-full border z-10',
            isLast ? 'border-cyan-700 bg-cyan-950' : 'border-border bg-card'
          )}
        >
          <Icon className={cn('h-3 w-3', config.color)} />
        </div>
      </div>

      <div className="flex-1 min-w-0 pb-2">
        <div className="flex items-baseline justify-between gap-2">
          <span className={cn('text-xs font-semibold font-mono', config.color)}>
            {config.label}
          </span>
          <span className="text-xs text-muted-foreground/60 shrink-0">{timestamp}</span>
        </div>

        {/* Show the event payload fields (anomaly_score, severity, etc.) in a small
            key:value grid so analysts can see what data arrived with each event. */}
        {dataKeys.length > 0 && (
          <div className="mt-1 rounded border border-border bg-muted/30 p-2 space-y-0.5">
            {dataKeys.slice(0, 4).map((key) => (
              <div key={key} className="flex gap-2 text-xs">
                <span className="text-muted-foreground font-mono shrink-0">{key}:</span>
                <span className="font-mono text-foreground/80 truncate">
                  {String(event.data[key])}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
