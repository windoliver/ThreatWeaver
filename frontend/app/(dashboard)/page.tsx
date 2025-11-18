import { Button } from '@/components/ui/button';
import { ArrowRight, Shield, Zap, Target, Database, Lock, Activity, CheckCircle2 } from 'lucide-react';

export default function HomePage() {
  return (
    <main className="min-h-screen">
      <section className="py-20 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-br from-green-950/20 via-background to-background" />
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative z-10">
          <div className="lg:grid lg:grid-cols-12 lg:gap-8">
            <div className="sm:text-center md:max-w-2xl md:mx-auto lg:col-span-6 lg:text-left">
              <div className="inline-block mb-4 px-3 py-1 bg-primary/10 border border-primary/30 rounded-full">
                <span className="text-primary text-sm font-mono cyber-glow">
                  ⚡ MULTI-AGENT SECURITY PLATFORM
                </span>
              </div>
              <h1 className="text-4xl font-bold tracking-tight sm:text-5xl md:text-6xl">
                <span className="block text-foreground">ThreatWeaver</span>
                <span className="block text-primary cyber-glow mt-2">
                  Autonomous Security
                </span>
              </h1>
              <p className="mt-6 text-base text-muted-foreground sm:mt-8 sm:text-xl lg:text-lg xl:text-xl font-mono">
                Advanced multi-agent cybersecurity platform powered by AI.
                Automated reconnaissance, vulnerability assessment, and
                intelligent threat detection with human-in-the-loop controls.
              </p>
              <div className="mt-8 sm:max-w-lg sm:mx-auto sm:text-center lg:text-left lg:mx-0 flex flex-col sm:flex-row gap-4">
                <a href="/sign-up">
                  <Button
                    size="lg"
                    className="w-full sm:w-auto bg-primary hover:bg-primary/90 text-primary-foreground cyber-border"
                  >
                    Start Free Trial
                    <ArrowRight className="ml-2 h-5 w-5" />
                  </Button>
                </a>
                <a href="/dashboard">
                  <Button
                    size="lg"
                    variant="outline"
                    className="w-full sm:w-auto border-primary/50 hover:bg-primary/10"
                  >
                    <Shield className="mr-2 h-5 w-5" />
                    View Demo
                  </Button>
                </a>
              </div>
              <div className="mt-8 flex items-center gap-6 text-sm text-muted-foreground font-mono justify-center lg:justify-start">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-primary rounded-full animate-pulse" />
                  <span>7 Active Agents</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 bg-primary rounded-full animate-pulse" />
                  <span>LangGraph Orchestration</span>
                </div>
              </div>
            </div>
            <div className="mt-12 relative sm:max-w-lg sm:mx-auto lg:mt-0 lg:max-w-none lg:mx-0 lg:col-span-6 lg:flex lg:items-center">
              <div className="w-full cyber-border bg-card p-8 rounded-lg">
                <h3 className="text-2xl font-bold text-foreground mb-6 font-mono cyber-glow">
                  Platform Features
                </h3>
                <div className="space-y-4">
                  {[
                    { icon: Zap, text: 'Automated Vulnerability Scanning' },
                    { icon: Target, text: 'AI-Powered Threat Detection' },
                    { icon: Shield, text: 'Real-Time Security Monitoring' },
                    { icon: Activity, text: 'Comprehensive Audit Logs' },
                    { icon: Lock, text: 'Human-in-the-Loop Approval' },
                    { icon: Database, text: 'Centralized Dashboard' }
                  ].map((feature, idx) => (
                    <div key={idx} className="flex items-center gap-3 group">
                      <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center cyber-border group-hover:bg-primary/20 transition-colors">
                        <feature.icon className="h-5 w-5 text-primary" />
                      </div>
                      <span className="text-foreground font-mono">{feature.text}</span>
                    </div>
                  ))}
                </div>
                <div className="mt-8 pt-6 border-t border-border">
                  <p className="text-sm text-muted-foreground font-mono text-center">
                    No installation required • Cloud-based • Enterprise-ready
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="py-16 relative">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-foreground mb-4">
              Multi-Agent Architecture
            </h2>
            <p className="text-muted-foreground font-mono max-w-2xl mx-auto">
              Coordinated AI agents working in parallel for comprehensive security assessment
            </p>
          </div>
          <div className="lg:grid lg:grid-cols-3 lg:gap-8">
            <div className="group hover:scale-105 transition-transform">
              <div className="cyber-border bg-card p-6 rounded-lg">
                <div className="flex items-center justify-center h-12 w-12 rounded-md bg-primary/10 text-primary mb-4 cyber-border">
                  <Zap className="h-6 w-6" />
                </div>
                <h3 className="text-lg font-semibold text-card-foreground mb-2 font-mono">
                  Recon Engine
                </h3>
                <p className="text-muted-foreground text-sm">
                  Automated reconnaissance with Subfinder, HTTPx, and Nmap.
                  Intelligent subdomain enumeration and service discovery.
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <span className="text-xs px-2 py-1 bg-primary/10 text-primary rounded border border-primary/30">
                    Subfinder
                  </span>
                  <span className="text-xs px-2 py-1 bg-primary/10 text-primary rounded border border-primary/30">
                    HTTPx
                  </span>
                  <span className="text-xs px-2 py-1 bg-primary/10 text-primary rounded border border-primary/30">
                    Nmap
                  </span>
                </div>
              </div>
            </div>

            <div className="mt-10 lg:mt-0 group hover:scale-105 transition-transform">
              <div className="cyber-border bg-card p-6 rounded-lg">
                <div className="flex items-center justify-center h-12 w-12 rounded-md bg-primary/10 text-primary mb-4 cyber-border">
                  <Target className="h-6 w-6" />
                </div>
                <h3 className="text-lg font-semibold text-card-foreground mb-2 font-mono">
                  Assessment Engine
                </h3>
                <p className="text-muted-foreground text-sm">
                  Vulnerability scanning with Nuclei and SQLMap. AI-powered
                  analysis and exploitation validation.
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <span className="text-xs px-2 py-1 bg-primary/10 text-primary rounded border border-primary/30">
                    Nuclei
                  </span>
                  <span className="text-xs px-2 py-1 bg-primary/10 text-primary rounded border border-primary/30">
                    SQLMap
                  </span>
                  <span className="text-xs px-2 py-1 bg-primary/10 text-primary rounded border border-primary/30">
                    AI Analysis
                  </span>
                </div>
              </div>
            </div>

            <div className="mt-10 lg:mt-0 group hover:scale-105 transition-transform">
              <div className="cyber-border bg-card p-6 rounded-lg">
                <div className="flex items-center justify-center h-12 w-12 rounded-md bg-primary/10 text-primary mb-4 cyber-border">
                  <Lock className="h-6 w-6" />
                </div>
                <h3 className="text-lg font-semibold text-card-foreground mb-2 font-mono">
                  HITL Controls
                </h3>
                <p className="text-muted-foreground text-sm">
                  Human-in-the-loop approval for high-risk actions. Comprehensive
                  audit logging and real-time monitoring.
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <span className="text-xs px-2 py-1 bg-primary/10 text-primary rounded border border-primary/30">
                    Approval Workflow
                  </span>
                  <span className="text-xs px-2 py-1 bg-primary/10 text-primary rounded border border-primary/30">
                    Audit Logs
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="py-16 relative border-t border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold text-foreground mb-4">
              Why Choose ThreatWeaver?
            </h2>
            <p className="text-muted-foreground font-mono max-w-2xl mx-auto">
              Enterprise-grade security platform designed for modern threat landscapes
            </p>
          </div>
          <div className="grid md:grid-cols-3 gap-8">
            <div className="cyber-border bg-card p-6 rounded-lg text-center group hover:scale-105 transition-transform">
              <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4 cyber-border group-hover:bg-primary/20 transition-colors">
                <Zap className="h-6 w-6 text-primary" />
              </div>
              <h3 className="text-xl font-bold text-foreground mb-2 font-mono">
                Lightning Fast
              </h3>
              <p className="text-muted-foreground text-sm">
                Automated scans complete in minutes, not hours. Get actionable
                insights without the wait.
              </p>
            </div>

            <div className="cyber-border bg-card p-6 rounded-lg text-center group hover:scale-105 transition-transform">
              <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4 cyber-border group-hover:bg-primary/20 transition-colors">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <h3 className="text-xl font-bold text-foreground mb-2 font-mono">
                Always Secure
              </h3>
              <p className="text-muted-foreground text-sm">
                Human oversight for critical actions. Full audit trails and
                compliance-ready reporting.
              </p>
            </div>

            <div className="cyber-border bg-card p-6 rounded-lg text-center group hover:scale-105 transition-transform">
              <div className="w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center mx-auto mb-4 cyber-border group-hover:bg-primary/20 transition-colors">
                <Activity className="h-6 w-6 text-primary" />
              </div>
              <h3 className="text-xl font-bold text-foreground mb-2 font-mono">
                Continuously Learning
              </h3>
              <p className="text-muted-foreground text-sm">
                AI agents improve with every scan, adapting to new threats
                and attack patterns automatically.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="py-16 border-t border-border">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="cyber-border bg-gradient-to-r from-primary/5 to-primary/10 p-12 rounded-lg text-center">
            <h2 className="text-3xl font-bold text-foreground sm:text-4xl mb-4 cyber-glow">
              Ready to Secure Your Infrastructure?
            </h2>
            <p className="text-muted-foreground mb-8 max-w-2xl mx-auto font-mono">
              Start your first automated security scan with AI-powered insights.
              Enterprise-grade protection with human oversight.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <a href="/dashboard">
                <Button
                  size="lg"
                  className="bg-primary hover:bg-primary/90 text-primary-foreground cyber-border"
                >
                  <Shield className="mr-2 h-5 w-5" />
                  Launch Dashboard
                </Button>
              </a>
              <a href="https://github.com/windoliver/ThreatWeaver" target="_blank">
                <Button
                  size="lg"
                  variant="outline"
                  className="border-primary/50 hover:bg-primary/10"
                >
                  View Documentation
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Button>
              </a>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}
