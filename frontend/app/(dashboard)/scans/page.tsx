'use client';

import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { Plus, Eye, Trash2, RefreshCw } from 'lucide-react';
import { ScanStatusBadge, ScanStatus } from '@/components/scan-status-badge';
import { useState } from 'react';

// Mock data - will be replaced with API calls
const mockScans = [
  {
    id: '1',
    target: 'example.com',
    scanType: 'Full Scan',
    status: 'completed' as ScanStatus,
    findings: 12,
    createdAt: '2025-01-15 14:30',
    duration: '5m 23s',
  },
  {
    id: '2',
    target: 'api.example.com',
    scanType: 'Recon Only',
    status: 'running' as ScanStatus,
    findings: 0,
    createdAt: '2025-01-15 15:45',
    duration: '-',
  },
  {
    id: '3',
    target: 'test.example.org',
    scanType: 'Vulnerability Scan',
    status: 'pending' as ScanStatus,
    findings: 0,
    createdAt: '2025-01-15 16:00',
    duration: '-',
  },
  {
    id: '4',
    target: 'staging.example.net',
    scanType: 'Full Scan',
    status: 'failed' as ScanStatus,
    findings: 0,
    createdAt: '2025-01-14 10:15',
    duration: '2m 10s',
  },
  {
    id: '5',
    target: 'app.example.io',
    scanType: 'Recon Only',
    status: 'completed' as ScanStatus,
    findings: 8,
    createdAt: '2025-01-14 09:30',
    duration: '3m 45s',
  },
];

export default function ScansPage() {
  const [scans, setScans] = useState(mockScans);
  const [currentPage, setCurrentPage] = useState(1);
  const scansPerPage = 10;

  // Calculate pagination
  const indexOfLastScan = currentPage * scansPerPage;
  const indexOfFirstScan = indexOfLastScan - scansPerPage;
  const currentScans = scans.slice(indexOfFirstScan, indexOfLastScan);
  const totalPages = Math.ceil(scans.length / scansPerPage);

  const handleDelete = (id: string) => {
    if (confirm('Are you sure you want to delete this scan?')) {
      setScans(scans.filter((scan) => scan.id !== id));
    }
  };

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold text-foreground font-mono cyber-glow">
              Security Scans
            </h1>
            <p className="text-muted-foreground mt-2 font-mono">
              Manage and monitor your automated security scans
            </p>
          </div>
          <Link href="/scans/new">
            <Button className="cyber-border bg-primary hover:bg-primary/90 font-mono">
              <Plus className="mr-2 h-4 w-4" />
              New Scan
            </Button>
          </Link>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <div className="cyber-border bg-card p-4 rounded-lg">
            <div className="text-sm text-muted-foreground font-mono">Total Scans</div>
            <div className="text-2xl font-bold text-foreground mt-1">{scans.length}</div>
          </div>
          <div className="cyber-border bg-card p-4 rounded-lg">
            <div className="text-sm text-muted-foreground font-mono">Running</div>
            <div className="text-2xl font-bold text-blue-500 mt-1">
              {scans.filter((s) => s.status === 'running').length}
            </div>
          </div>
          <div className="cyber-border bg-card p-4 rounded-lg">
            <div className="text-sm text-muted-foreground font-mono">Completed</div>
            <div className="text-2xl font-bold text-primary mt-1">
              {scans.filter((s) => s.status === 'completed').length}
            </div>
          </div>
          <div className="cyber-border bg-card p-4 rounded-lg">
            <div className="text-sm text-muted-foreground font-mono">Total Findings</div>
            <div className="text-2xl font-bold text-foreground mt-1">
              {scans.reduce((acc, scan) => acc + scan.findings, 0)}
            </div>
          </div>
        </div>

        {/* Table */}
        <div className="cyber-border bg-card rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead className="bg-secondary border-b border-border">
                <tr>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider font-mono">
                    Target
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider font-mono">
                    Type
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider font-mono">
                    Status
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider font-mono">
                    Findings
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider font-mono">
                    Created
                  </th>
                  <th className="px-6 py-3 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider font-mono">
                    Duration
                  </th>
                  <th className="px-6 py-3 text-right text-xs font-medium text-muted-foreground uppercase tracking-wider font-mono">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {currentScans.map((scan) => (
                  <tr key={scan.id} className="hover:bg-secondary/50 transition-colors">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-foreground font-mono">
                        {scan.target}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-muted-foreground font-mono">
                        {scan.scanType}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <ScanStatusBadge status={scan.status} />
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className={`text-sm font-mono ${scan.findings > 0 ? 'text-primary font-bold' : 'text-muted-foreground'}`}>
                        {scan.findings > 0 ? scan.findings : '-'}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-muted-foreground font-mono">
                        {scan.createdAt}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm text-muted-foreground font-mono">
                        {scan.duration}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                      <div className="flex gap-2 justify-end">
                        <Link href={`/scans/${scan.id}`}>
                          <Button
                            variant="outline"
                            size="sm"
                            className="border-primary/30 hover:bg-primary/10"
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                        </Link>
                        {scan.status === 'failed' && (
                          <Button
                            variant="outline"
                            size="sm"
                            className="border-blue-500/30 hover:bg-blue-500/10"
                          >
                            <RefreshCw className="h-4 w-4" />
                          </Button>
                        )}
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleDelete(scan.id)}
                          className="border-red-500/30 hover:bg-red-500/10"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="px-6 py-4 border-t border-border flex items-center justify-between">
              <div className="text-sm text-muted-foreground font-mono">
                Showing {indexOfFirstScan + 1} to {Math.min(indexOfLastScan, scans.length)} of{' '}
                {scans.length} scans
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage((prev) => Math.max(prev - 1, 1))}
                  disabled={currentPage === 1}
                  className="font-mono"
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setCurrentPage((prev) => Math.min(prev + 1, totalPages))}
                  disabled={currentPage === totalPages}
                  className="font-mono"
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
