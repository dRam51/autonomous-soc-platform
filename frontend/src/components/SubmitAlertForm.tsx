'use client';

import * as React from 'react';
import { createAlert, type AlertCreate } from '@/lib/api';
import { Button } from './ui/button';
import { Input } from './ui/input';
import { Label } from './ui/label';
import { Textarea } from './ui/textarea';
import { cn } from '@/lib/utils';
import { ChevronDown, ChevronUp, Send, CheckCircle, AlertTriangle } from 'lucide-react';

// The source options correspond to common enterprise security tool categories.
// These become the alert.source field which the anomaly detection feature extractor
// uses as a hash-bucketed numeric feature to learn normal patterns per source system.
const SOURCE_OPTIONS = [
  'SIEM',
  'EDR',
  'IDS',
  'Firewall',
  'Email Gateway',
  'Manual',
];

interface SubmitAlertFormProps {
  onSuccess?: (id: string) => void;
}

// FormState machine: idle -> submitting -> success|error -> idle
// Using a discriminated union string instead of multiple boolean flags prevents
// impossible states like {submitting: true, success: true}.
type FormState = 'idle' | 'submitting' | 'success' | 'error';

export function SubmitAlertForm({ onSuccess }: SubmitAlertFormProps) {
  const [formState, setFormState] = React.useState<FormState>('idle');
  const [errorMessage, setErrorMessage] = React.useState('');
  // Raw log is hidden behind a toggle to reduce visual clutter for simple alerts.
  // Most alerts do not need the raw log field, so it is collapsed by default.
  const [showRawLog, setShowRawLog] = React.useState(false);

  const [title, setTitle] = React.useState('');
  const [description, setDescription] = React.useState('');
  const [source, setSource] = React.useState('SIEM');
  const [sourceIp, setSourceIp] = React.useState('');
  const [destinationIp, setDestinationIp] = React.useState('');
  const [affectedHost, setAffectedHost] = React.useState('');
  const [iocs, setIocs] = React.useState('');
  const [rawLog, setRawLog] = React.useState('');

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!title.trim() || !description.trim()) return;

    setFormState('submitting');
    setErrorMessage('');

    // Build the payload with optional fields only included when they have values.
    // The spread pattern (..condition && {field: value}) avoids sending empty strings
    // to the backend, which would fail Pydantic's Optional[str] validation for IP fields.
    const payload: AlertCreate = {
      title: title.trim(),
      description: description.trim(),
      source,
      ...(sourceIp.trim() && { source_ip: sourceIp.trim() }),
      ...(destinationIp.trim() && { destination_ip: destinationIp.trim() }),
      ...(affectedHost.trim() && { affected_host: affectedHost.trim() }),
      ...(iocs.trim() && {
        // Parse comma-separated IOCs into an array, stripping whitespace and empty entries.
        iocs: iocs
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean),
      }),
      ...(rawLog.trim() && { raw_log: rawLog.trim() }),
    };

    try {
      const result = await createAlert(payload);
      setFormState('success');
      // Brief success display before resetting and selecting the new alert.
      // 1500ms is enough for the user to register success without feeling slow.
      setTimeout(() => {
        setFormState('idle');
        setTitle('');
        setDescription('');
        setSource('SIEM');
        setSourceIp('');
        setDestinationIp('');
        setAffectedHost('');
        setIocs('');
        setRawLog('');
        // Notify the parent to select the new alert, which opens its SSE stream.
        onSuccess?.(result.id);
      }, 1500);
    } catch (err) {
      setFormState('error');
      setErrorMessage(err instanceof Error ? err.message : 'Failed to submit alert');
    }
  };

  if (formState === 'success') {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-8 text-green-400">
        <CheckCircle className="h-10 w-10" />
        <p className="font-medium">Alert submitted successfully</p>
        <p className="text-sm text-muted-foreground">Pipeline processing...</p>
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <div className="space-y-1.5">
        <Label htmlFor="title">
          Title <span className="text-red-400">*</span>
        </Label>
        <Input
          id="title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
          placeholder="Suspicious lateral movement detected"
          required
          disabled={formState === 'submitting'}
        />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="description">
          Description <span className="text-red-400">*</span>
        </Label>
        {/* Description is the primary semantic input for both the deduplication
            embedding and the triage agent. More detail here improves pipeline accuracy. */}
        <Textarea
          id="description"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Detailed description of the alert..."
          rows={3}
          required
          disabled={formState === 'submitting'}
        />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="source">
          Source <span className="text-red-400">*</span>
        </Label>
        <select
          id="source"
          value={source}
          onChange={(e) => setSource(e.target.value)}
          disabled={formState === 'submitting'}
          className={cn(
            'flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm',
            'ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
            'disabled:cursor-not-allowed disabled:opacity-50'
          )}
        >
          {SOURCE_OPTIONS.map((opt) => (
            <option key={opt} value={opt}>
              {opt}
            </option>
          ))}
        </select>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <Label htmlFor="source_ip">Source IP</Label>
          {/* IP fields feed the anomaly detection feature extractor (public vs private)
              and the memory module (entity lookup for prior incidents). */}
          <Input
            id="source_ip"
            value={sourceIp}
            onChange={(e) => setSourceIp(e.target.value)}
            placeholder="192.168.1.100"
            className="font-mono"
            disabled={formState === 'submitting'}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="dest_ip">Destination IP</Label>
          <Input
            id="dest_ip"
            value={destinationIp}
            onChange={(e) => setDestinationIp(e.target.value)}
            placeholder="10.0.0.1"
            className="font-mono"
            disabled={formState === 'submitting'}
          />
        </div>
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="affected_host">Affected Host</Label>
        {/* Affected host is stored in agent memory after each incident so future
            alerts about the same host get historical context automatically. */}
        <Input
          id="affected_host"
          value={affectedHost}
          onChange={(e) => setAffectedHost(e.target.value)}
          placeholder="WORKSTATION-042"
          className="font-mono"
          disabled={formState === 'submitting'}
        />
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="iocs">
          IOCs{' '}
          <span className="text-muted-foreground text-xs">(comma-separated)</span>
        </Label>
        {/* IOCs (Indicators of Compromise) are checked against VirusTotal by the
            threat intel agent. Provide file hashes, IPs, or domains here. */}
        <Input
          id="iocs"
          value={iocs}
          onChange={(e) => setIocs(e.target.value)}
          placeholder="hash123, evil.com, 1.2.3.4"
          className="font-mono"
          disabled={formState === 'submitting'}
        />
      </div>

      <div>
        <button
          type="button"
          onClick={() => setShowRawLog(!showRawLog)}
          className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors mb-2"
          disabled={formState === 'submitting'}
        >
          {showRawLog ? (
            <ChevronUp className="h-3.5 w-3.5" />
          ) : (
            <ChevronDown className="h-3.5 w-3.5" />
          )}
          Raw Log (optional)
        </button>

        {showRawLog && (
          // Raw log content is passed directly to agents for analysis.
          // SIEM or EDR raw event data pasted here gives the investigation agent
          // maximum context for timeline reconstruction.
          <Textarea
            value={rawLog}
            onChange={(e) => setRawLog(e.target.value)}
            placeholder="Paste raw log data here..."
            rows={4}
            className="font-mono text-xs"
            disabled={formState === 'submitting'}
          />
        )}
      </div>

      {formState === 'error' && (
        <div className="flex items-start gap-2 rounded-md border border-red-800 bg-red-950/50 p-3 text-red-400">
          <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" />
          <p className="text-sm">{errorMessage}</p>
        </div>
      )}

      <Button
        type="submit"
        disabled={formState === 'submitting' || !title.trim() || !description.trim()}
        className="w-full"
      >
        {formState === 'submitting' ? (
          <>
            <RefreshCwIcon className="mr-2 h-4 w-4 animate-spin" />
            Submitting...
          </>
        ) : (
          <>
            <Send className="mr-2 h-4 w-4" />
            Submit Alert
          </>
        )}
      </Button>
    </form>
  );
}

// Inline SVG spinner avoids importing the full lucide-react RefreshCw
// (which would also render as a static icon without the animate-spin class applied).
function RefreshCwIcon({ className }: { className?: string }) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8" />
      <path d="M21 3v5h-5" />
      <path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16" />
      <path d="M8 16H3v5" />
    </svg>
  );
}
