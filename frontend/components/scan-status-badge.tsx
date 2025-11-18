import { cn } from '@/lib/utils';

export type ScanStatus =
  | 'pending'
  | 'running'
  | 'completed'
  | 'failed'
  | 'cancelled';

interface ScanStatusBadgeProps {
  status: ScanStatus;
  className?: string;
}

const statusConfig: Record<ScanStatus, { label: string; className: string }> = {
  pending: {
    label: 'Pending',
    className: 'bg-yellow-500/10 text-yellow-500 border-yellow-500/30',
  },
  running: {
    label: 'Running',
    className: 'bg-blue-500/10 text-blue-500 border-blue-500/30 animate-pulse',
  },
  completed: {
    label: 'Completed',
    className: 'bg-primary/10 text-primary border-primary/30',
  },
  failed: {
    label: 'Failed',
    className: 'bg-red-500/10 text-red-500 border-red-500/30',
  },
  cancelled: {
    label: 'Cancelled',
    className: 'bg-gray-500/10 text-gray-500 border-gray-500/30',
  },
};

export function ScanStatusBadge({ status, className }: ScanStatusBadgeProps) {
  const config = statusConfig[status];

  return (
    <span
      className={cn(
        'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium border font-mono',
        config.className,
        className
      )}
    >
      {config.label}
    </span>
  );
}
