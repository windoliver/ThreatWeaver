'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { Button } from '@/components/ui/button';
import { ArrowLeft, Shield } from 'lucide-react';

export default function NewScanPage() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [formData, setFormData] = useState({
    target: '',
    scanType: 'full',
    schedule: 'immediate',
    notifications: true,
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);

    // TODO: Replace with actual API call
    await new Promise((resolve) => setTimeout(resolve, 1500));

    console.log('Creating scan with data:', formData);

    // Redirect to scans list
    router.push('/scans');
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const { name, value, type } = e.target;
    const checked = (e.target as HTMLInputElement).checked;

    setFormData((prev) => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value,
    }));
  };

  return (
    <div className="min-h-screen p-8">
      <div className="max-w-3xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <Link href="/scans">
            <Button variant="outline" className="mb-4 border-primary/30 hover:bg-primary/10 font-mono">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back to Scans
            </Button>
          </Link>
          <h1 className="text-3xl font-bold text-foreground font-mono cyber-glow">
            Create New Scan
          </h1>
          <p className="text-muted-foreground mt-2 font-mono">
            Configure and launch an automated security scan
          </p>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="cyber-border bg-card p-8 rounded-lg space-y-6">
          {/* Target */}
          <div>
            <label htmlFor="target" className="block text-sm font-medium text-foreground font-mono mb-2">
              Target Domain or IP *
            </label>
            <input
              type="text"
              id="target"
              name="target"
              required
              value={formData.target}
              onChange={handleChange}
              placeholder="example.com or 192.168.1.1"
              className="w-full px-4 py-2 bg-input border border-border rounded-md text-foreground font-mono focus:outline-none focus:ring-2 focus:ring-primary"
            />
            <p className="mt-1 text-xs text-muted-foreground font-mono">
              Enter the domain name or IP address to scan
            </p>
          </div>

          {/* Scan Type */}
          <div>
            <label htmlFor="scanType" className="block text-sm font-medium text-foreground font-mono mb-2">
              Scan Type *
            </label>
            <select
              id="scanType"
              name="scanType"
              required
              value={formData.scanType}
              onChange={handleChange}
              className="w-full px-4 py-2 bg-input border border-border rounded-md text-foreground font-mono focus:outline-none focus:ring-2 focus:ring-primary"
            >
              <option value="full">Full Scan (Recon + Vulnerability Assessment)</option>
              <option value="recon">Recon Only (Subfinder, HTTPx, Nmap)</option>
              <option value="vulnerability">Vulnerability Scan Only (Nuclei, SQLMap)</option>
              <option value="quick">Quick Scan (Fast Overview)</option>
            </select>
            <p className="mt-1 text-xs text-muted-foreground font-mono">
              Full scans may take longer but provide comprehensive results
            </p>
          </div>

          {/* Scan Options */}
          <div className="space-y-4">
            <h3 className="text-sm font-medium text-foreground font-mono">Scan Options</h3>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="cyber-border bg-secondary p-4 rounded-md">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    name="subdomain_enum"
                    defaultChecked
                    className="mt-1 w-4 h-4 text-primary bg-input border-border rounded focus:ring-primary"
                  />
                  <div>
                    <div className="text-sm font-medium text-foreground font-mono">
                      Subdomain Enumeration
                    </div>
                    <div className="text-xs text-muted-foreground font-mono mt-1">
                      Discover subdomains using Subfinder
                    </div>
                  </div>
                </label>
              </div>

              <div className="cyber-border bg-secondary p-4 rounded-md">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    name="port_scan"
                    defaultChecked
                    className="mt-1 w-4 h-4 text-primary bg-input border-border rounded focus:ring-primary"
                  />
                  <div>
                    <div className="text-sm font-medium text-foreground font-mono">
                      Port Scanning
                    </div>
                    <div className="text-xs text-muted-foreground font-mono mt-1">
                      Scan for open ports with Nmap
                    </div>
                  </div>
                </label>
              </div>

              <div className="cyber-border bg-secondary p-4 rounded-md">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    name="vuln_scan"
                    defaultChecked
                    className="mt-1 w-4 h-4 text-primary bg-input border-border rounded focus:ring-primary"
                  />
                  <div>
                    <div className="text-sm font-medium text-foreground font-mono">
                      Vulnerability Detection
                    </div>
                    <div className="text-xs text-muted-foreground font-mono mt-1">
                      Find vulnerabilities with Nuclei
                    </div>
                  </div>
                </label>
              </div>

              <div className="cyber-border bg-secondary p-4 rounded-md">
                <label className="flex items-start gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    name="sql_injection"
                    className="mt-1 w-4 h-4 text-primary bg-input border-border rounded focus:ring-primary"
                  />
                  <div>
                    <div className="text-sm font-medium text-foreground font-mono">
                      SQL Injection Testing
                    </div>
                    <div className="text-xs text-muted-foreground font-mono mt-1">
                      Test for SQL injections with SQLMap
                    </div>
                  </div>
                </label>
              </div>
            </div>
          </div>

          {/* Schedule */}
          <div>
            <label htmlFor="schedule" className="block text-sm font-medium text-foreground font-mono mb-2">
              Schedule
            </label>
            <select
              id="schedule"
              name="schedule"
              value={formData.schedule}
              onChange={handleChange}
              className="w-full px-4 py-2 bg-input border border-border rounded-md text-foreground font-mono focus:outline-none focus:ring-2 focus:ring-primary"
            >
              <option value="immediate">Run Immediately</option>
              <option value="scheduled">Schedule for Later</option>
              <option value="recurring">Recurring Scan</option>
            </select>
          </div>

          {/* Notifications */}
          <div className="cyber-border bg-secondary p-4 rounded-md">
            <label className="flex items-start gap-3 cursor-pointer">
              <input
                type="checkbox"
                name="notifications"
                checked={formData.notifications}
                onChange={handleChange}
                className="mt-1 w-4 h-4 text-primary bg-input border-border rounded focus:ring-primary"
              />
              <div>
                <div className="text-sm font-medium text-foreground font-mono">
                  Email Notifications
                </div>
                <div className="text-xs text-muted-foreground font-mono mt-1">
                  Receive email alerts when scan completes or finds critical vulnerabilities
                </div>
              </div>
            </label>
          </div>

          {/* Submit */}
          <div className="flex gap-4 pt-4">
            <Button
              type="submit"
              disabled={loading || !formData.target}
              className="flex-1 cyber-border bg-primary hover:bg-primary/90 font-mono"
            >
              {loading ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-2 border-background border-t-transparent mr-2" />
                  Launching Scan...
                </>
              ) : (
                <>
                  <Shield className="mr-2 h-4 w-4" />
                  Launch Scan
                </>
              )}
            </Button>
            <Link href="/scans" className="flex-1">
              <Button
                type="button"
                variant="outline"
                className="w-full border-border hover:bg-secondary font-mono"
                disabled={loading}
              >
                Cancel
              </Button>
            </Link>
          </div>
        </form>

        {/* Info Box */}
        <div className="mt-6 cyber-border bg-card p-6 rounded-lg">
          <h3 className="text-sm font-bold text-primary font-mono mb-2">
            ⚡ Human-in-the-Loop Controls
          </h3>
          <p className="text-sm text-muted-foreground font-mono">
            High-risk actions (like SQL injection testing) require manual approval before execution.
            You'll receive a notification when approval is needed.
          </p>
        </div>
      </div>
    </div>
  );
}
