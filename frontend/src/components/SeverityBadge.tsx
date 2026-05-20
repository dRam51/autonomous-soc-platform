import * as React from 'react';
import { cn } from '@/lib/utils';
import type { SeverityLevel } from '@/lib/api';

const severityConfig: Record<
  SeverityLevel,
  { label: string; className: string }
> = {
  critical: {
    label: 'CRITICAL',
    className:
      'bg-red-950 text-red-400 border-red-800 ring-1 ring-red-700',
  },
  high: {
    label: 'HIGH',
    className:
      'bg-orange-950 text-orange-400 border-orange-800',
  },
  medium: {
    label: 'MEDIUM',
    className:
      'bg-yellow-950 text-yellow-400 border-yellow-800',
  },
  low: {
    label: 'LOW',
    className:
      'bg-blue-950 text-blue-400 border-blue-800',
  },
  info: {
    label: 'INFO',
    className:
      'bg-slate-800 text-slate-400 border-slate-600',
  },
};

interface SeverityBadgeProps {
  severity?: SeverityLevel;
  className?: string;
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  if (!severity) {
    return (
      <span
        className={cn(
          'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-mono font-semibold',
          'bg-slate-800 text-slate-500 border-slate-700',
          className
        )}
      >
        UNKNOWN
      </span>
    );
  }

  const config = severityConfig[severity];

  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-mono font-semibold',
        config.className,
        className
      )}
    >
      {config.label}
    </span>
  );
}
