# ThreatWeaver Frontend

Next.js 14+ frontend for ThreatWeaver SaaS platform.

## Structure

```
frontend/
├── app/                  # Next.js App Router
│   ├── (auth)/           # Auth pages (login, signup)
│   ├── (dashboard)/      # Dashboard pages (scans, findings, approvals)
│   └── api/              # API routes (NextAuth, Stripe webhooks)
├── components/           # React components
│   ├── ui/               # shadcn/ui components
│   └── features/         # Feature-specific components
├── lib/                  # Utilities
├── public/               # Static assets
├── package.json
└── Dockerfile
```

## Getting Started

See [Issue #7](https://github.com/windoliver/ThreatWeaver/issues/7) for frontend setup.

## Tech Stack

- **Framework**: Next.js 14+ (App Router)
- **UI**: shadcn/ui, Tailwind CSS, Radix UI
- **Auth**: NextAuth.js
- **Payments**: Stripe
- **ORM**: Drizzle ORM
- **State**: TanStack Query, Zustand

## Documentation

- [Contributing](../CONTRIBUTING.md) - Development guidelines
