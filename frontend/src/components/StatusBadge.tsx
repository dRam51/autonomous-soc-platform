import * as React from 'react';
import { cn } from '@/lib/utils';
import type { AlertStatus } from '@/lib/api';
import {
  Sparkles,
  Search,
  Microscope,
  Wrench,
  CheckCircle,
  Ban,
} from 'lucide-react';

const statusConfig: Record<
  AlertStatus,
  { label: string; className: string; Icon: React.ElementType }
> = {
  new: {
    label: 'NEW',
    className: 'bg-cyan-950 text-cyan-400 border-cyan-800',
    Icon: Sparkles,
  },
  triaging: {
    label: 'TRIAGING',
    className: 'bg-purple-950 text-purple-400 border-purple-800',
    Icon: Search,
  },
  investigating: {
    label: 'INVESTIGATING',
    className: 'bg-blue-950 text-blue-400 border-blue-800',
    Icon: Microscope,
  },
  remediating: {
    label: 'REMEDIATING',
    className: 'bg-orange-950 text-orange-400 border-orange-800',
    Icon: Wrench,
  },
  closed: {
    label: 'CLOSED',
    className: 'bg-green-950 text-green-400 border-green-800',
    Icon: CheckCircle,
  },
  false_positive: {
    label: 'FALSE POS',
    className: 'bg-slate-800 text-slate-400 border-slate-600',
    Icon: Ban,
  },
};

interface StatusBadgeProps {
  status: AlertStatus;
  className?: string;
}

export function StatusBadge({ status, className }: StatusBadgeProps) {
  const config = statusConfig[status];
  const { Icon } = config;

  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-mono font-semibold',
        config.className,
        className
      )}
    >
      <Icon className="h-3 w-3" />
      {config.label}
    </span>
  );
}
