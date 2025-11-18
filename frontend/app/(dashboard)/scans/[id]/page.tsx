'use client';

import { use, useState } from 'react';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { ArrowLeft, Download, RefreshCw, AlertTriangle, CheckCircle2, Info } from 'lucide-react';
import { ScanStatusBadge, ScanStatus } from '@/components/scan-status-badge';

// Mock data - will be replaced with API calls
const mockScanDetails = {
  id: '1',
  target: 'example.com',
  scanType: 'Full Scan',
  status: 'completed' as ScanStatus,
  createdAt: '2025-01-15 14:30',
  completedAt: '2025-01-15 14:35',
  duration: '5m 23s',
  findings: {
    critical: 2,
    high: 4,
    medium: 5,
    low: 1,
    info: 0,
  },
  details: [
    {
      id: '1',
      severity: 'critical',
      title: 'SQL Injection Vulnerability',
      description: 'Detected SQL injection vulnerability in login form',
      location: 'https://example.com/login',
      recommendation: 'Use parameterized queries and input validation',
    },
    {
      id: '2',
      severity: 'critical',
      title: 'Exposed Admin Panel',
      description: 'Admin panel accessible without authentication',
      location: 'https://example.com/admin',
      recommendation: 'Implement proper authentication and access controls',
    },
    {
      id: '3',
      severity: 'high',
      title: 'Outdated Software Version',
      description: 'Running outdated version of Apache (2.4.29)',
      location: 'Server Header',
      recommendation: 'Update to latest stable version',
    },
    {
      id: '4',
      severity: 'high',
      title: 'Cross-Site Scripting (XSS)',
      description: 'Reflected XSS vulnerability in search parameter',
      location: 'https://example.com/search?q=',
      recommendation: 'Sanitize and encode user input',
    },
  ],
  agents: [
    { name: 'Subfinder', status: 'completed', findings: 12, duration: '45s' },
    { name: 'HTTPx', status: 'completed', findings: 8, duration: '1m 20s' },
    { name: 'Nmap', status: 'completed', findings: 5, duration: '2m 15s' },
    { name: 'Nuclei', status: 'completed', findings: 6, duration: '1m 3s' },
  ],
};

const severityConfig = {
  critical: { color: 'text-red-500', bg: 'bg-red-500/10', border: 'border-red-500/30', label: 'Critical' },
  high: { color: 'text-orange-500', bg: 'bg-orange-500/10', border: 'border-orange-500/30', label: 'High' },
  medium: { color: 'text-yellow-500', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', label: 'Medium' },
  low: { color: 'text-blue-500', bg: 'bg-blue-500/10', border: 'border-blue-500/30', label: 'Low' },
  info: { color: 'text-gray-500', bg: 'bg-gray-500/10', border: 'border-gray-500/30', label: 'Info' },
};

export default function ScanDetailsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [scan] = useState(mockScanDetails);
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);

  const filteredDetails = selectedSeverity
    ? scan.details.filter((d) => d.severity === selectedSeverity)
    : scan.details;

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
      case 'high':
        return <AlertTriangle className="h-5 w-5" />;
      case 'medium':
        return <Info className="h-5 w-5" />;
      default:
        return <CheckCircle2 className="h-5 w-5" />;
    }
  };

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <Link href="/scans">
            <Button variant="outline" className="mb-4 border-primary/30 hover:bg-primary/10 font-mono">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Scans
            </Button>
          </Link>
          <div className="flex justify-between items-start">
            <div>
              <div className="flex items-center gap-3 mb-2">
                <h1 className="text-3xl font-bold text-foreground font-mono cyber-glow">
                  {scan.target}
                </h1>
                <ScanStatusBadge status={scan.status} />
              </div>
              <p className="text-muted-foreground font-mono">
                {scan.scanType} • Started {scan.createdAt} • Duration: {scan.duration}
              </p>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" className="border-primary/30 hover:bg-primary/10 font-mono">
                <RefreshCw className="mr-2 h-4 w-4" />
                Re-scan
              </Button>
              <Button variant="outline" className="border-primary/30 hover:bg-primary/10 font-mono">
                <Download className="mr-2 h-4 w-4" />
                Export
              </Button>
            </div>
          </div>
        </div>

        {/* Findings Summary */}
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-8">
          {Object.entries(scan.findings).map(([severity, count]) => {
            const config = severityConfig[severity as keyof typeof severityConfig];
            return (
              <button
                key={severity}
                onClick={() => setSelectedSeverity(selectedSeverity === severity ? null : severity)}
                className={`cyber-border bg-card p-4 rounded-lg text-left hover:scale-105 transition-transform ${
                  selectedSeverity === severity ? 'ring-2 ring-primary' : ''
                }`}
              >
                <div className="text-xs text-muted-foreground font-mono uppercase mb-1">
                  {config.label}
                </div>
                <div className={`text-3xl font-bold ${config.color}`}>{count}</div>
              </button>
            );
          })}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Findings List */}
          <div className="lg:col-span-2 space-y-4">
            <h2 className="text-xl font-bold text-foreground font-mono mb-4">
              Findings {selectedSeverity && `(${severityConfig[selectedSeverity as keyof typeof severityConfig].label})`}
            </h2>
            {filteredDetails.map((finding) => {
              const config = severityConfig[finding.severity as keyof typeof severityConfig];
              return (
                <div key={finding.id} className={`cyber-border bg-card p-6 rounded-lg border ${config.border}`}>
                  <div className="flex items-start gap-4">
                    <div className={`${config.color} ${config.bg} p-2 rounded-lg`}>
                      {getSeverityIcon(finding.severity)}
                    </div>
                    <div className="flex-1">
                      <div className="flex items-start justify-between mb-2">
                        <h3 className="text-lg font-bold text-foreground font-mono">
                          {finding.title}
                        </h3>
                        <span className={`text-xs px-2 py-1 rounded-full font-mono ${config.bg} ${config.color} border ${config.border}`}>
                          {config.label}
                        </span>
                      </div>
                      <p className="text-sm text-muted-foreground font-mono mb-3">
                        {finding.description}
                      </p>
                      <div className="space-y-2">
                        <div>
                          <span className="text-xs text-muted-foreground font-mono">Location:</span>
                          <p className="text-sm text-primary font-mono break-all">{finding.location}</p>
                        </div>
                        <div>
                          <span className="text-xs text-muted-foreground font-mono">Recommendation:</span>
                          <p className="text-sm text-foreground font-mono">{finding.recommendation}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Agent Status */}
          <div className="space-y-4">
            <h2 className="text-xl font-bold text-foreground font-mono mb-4">
              Agent Status
            </h2>
            <div className="cyber-border bg-card rounded-lg overflow-hidden">
              {scan.agents.map((agent, idx) => (
                <div
                  key={idx}
                  className={`p-4 ${idx !== scan.agents.length - 1 ? 'border-b border-border' : ''}`}
                >
                  <div className="flex justify-between items-start mb-2">
                    <div className="font-bold text-foreground font-mono">{agent.name}</div>
                    <ScanStatusBadge status={agent.status as ScanStatus} />
                  </div>
                  <div className="text-xs text-muted-foreground font-mono space-y-1">
                    <div>Findings: <span className="text-primary">{agent.findings}</span></div>
                    <div>Duration: {agent.duration}</div>
                  </div>
                </div>
              ))}
            </div>

            {/* Scan Info */}
            <div className="cyber-border bg-card p-4 rounded-lg">
              <h3 className="text-sm font-bold text-foreground font-mono mb-3">
                Scan Information
              </h3>
              <div className="space-y-2 text-xs font-mono">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Scan ID:</span>
                  <span className="text-foreground">{scan.id}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Type:</span>
                  <span className="text-foreground">{scan.scanType}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Started:</span>
                  <span className="text-foreground">{scan.createdAt}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Completed:</span>
                  <span className="text-foreground">{scan.completedAt}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Duration:</span>
                  <span className="text-primary">{scan.duration}</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
