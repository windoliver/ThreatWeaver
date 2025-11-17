# Database Schema Documentation

ThreatWeaver uses PostgreSQL with SQLAlchemy async ORM and Alembic for migrations.

## Overview

The database schema supports:
- Multi-tenancy through Teams
- Security scan management
- Vulnerability/finding tracking
- Human-in-the-loop approval workflow

## Entity Relationship Diagram

```
┌──────────┐       ┌──────────────┐       ┌──────┐
│  User    │◄─────►│ TeamMember   │◄─────►│ Team │
└──────────┘       └──────────────┘       └───┬──┘
                                               │
                                               │ 1:N
                                               ▼
                                          ┌────────┐
                                          │  Scan  │
                                          └───┬─┬──┘
                                              │ │
                                         1:N  │ │ 1:N
                                              │ │
                          ┌───────────────────┘ └─────────────────┐
                          ▼                                        ▼
                   ┌──────────┐                          ┌─────────────────┐
                   │ Finding  │                          │ ApprovalRequest │
                   └──────────┘                          └─────────────────┘
```

## Tables

### users
Stores user account information.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PK, AUTO_INCREMENT | Unique user ID |
| email | VARCHAR(255) | UNIQUE, NOT NULL, INDEXED | User email address |
| username | VARCHAR(100) | UNIQUE, NOT NULL, INDEXED | Username |
| hashed_password | VARCHAR(255) | NOT NULL | Bcrypt hashed password |
| full_name | VARCHAR(255) | NULLABLE | User's full name |
| is_active | BOOLEAN | NOT NULL, DEFAULT TRUE | Account active status |
| is_superuser | BOOLEAN | NOT NULL, DEFAULT FALSE | Admin privileges |
| created_at | TIMESTAMP WITH TZ | NOT NULL, DEFAULT NOW() | Creation timestamp |
| updated_at | TIMESTAMP WITH TZ | NOT NULL, DEFAULT NOW() | Last update timestamp |

**Indexes:**
- `ix_users_email` on `email`
- `ix_users_username` on `username`

---

### teams
Multi-tenant organization/team management.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PK, AUTO_INCREMENT | Unique team ID |
| name | VARCHAR(255) | UNIQUE, NOT NULL, INDEXED | Team name |
| slug | VARCHAR(100) | UNIQUE, NOT NULL, INDEXED | URL-friendly team identifier |
| description | VARCHAR(500) | NULLABLE | Team description |
| created_at | TIMESTAMP WITH TZ | NOT NULL, DEFAULT NOW() | Creation timestamp |
| updated_at | TIMESTAMP WITH TZ | NOT NULL, DEFAULT NOW() | Last update timestamp |

**Indexes:**
- `ix_teams_name` on `name`
- `ix_teams_slug` on `slug`

---

### team_members
Association table for users and teams with roles.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PK, AUTO_INCREMENT | Unique membership ID |
| team_id | INTEGER | FK(teams.id), NOT NULL, INDEXED | Team reference |
| user_id | INTEGER | FK(users.id), NOT NULL, INDEXED | User reference |
| role | VARCHAR(50) | NOT NULL, DEFAULT 'member' | Role: owner, admin, member, viewer |
| created_at | TIMESTAMP WITH TZ | NOT NULL, DEFAULT NOW() | Creation timestamp |
| updated_at | TIMESTAMP WITH TZ | NOT NULL, DEFAULT NOW() | Last update timestamp |

**Constraints:**
- `uq_team_user`: UNIQUE(team_id, user_id)
- `ON DELETE CASCADE` for both foreign keys

**Indexes:**
- `ix_team_members_team_id` on `team_id`
- `ix_team_members_user_id` on `user_id`

---

### scans
Security scan/assessment records.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PK, AUTO_INCREMENT | Unique scan ID |
| team_id | INTEGER | FK(teams.id), NOT NULL, INDEXED | Team that owns this scan |
| name | VARCHAR(255) | NOT NULL | Scan name/title |
| description | TEXT | NULLABLE | Detailed description |
| target | VARCHAR(500) | NOT NULL, INDEXED | Scan target (domain, IP, etc.) |
| scan_type | VARCHAR(50) | NOT NULL, DEFAULT 'full' | Type: full, recon_only, assessment_only |
| status | VARCHAR(50) | NOT NULL, INDEXED, DEFAULT 'pending' | Status: pending, running, completed, failed, cancelled |
| config | JSONB | NOT NULL, DEFAULT {} | Scan configuration (tools, options) |
| recon_results | JSONB | NULLABLE | Reconnaissance phase results |
| assessment_results | JSONB | NULLABLE | Assessment phase results |
| agent_logs | JSONB | NULLABLE | Agent execution logs |
| error_message | TEXT | NULLABLE | Error details if failed |
| created_at | TIMESTAMP WITH TZ | NOT NULL, DEFAULT NOW() | Creation timestamp |
| updated_at | TIMESTAMP WITH TZ | NOT NULL, DEFAULT NOW() | Last update timestamp |

**Constraints:**
- `ON DELETE CASCADE` for team_id foreign key

**Indexes:**
- `ix_scans_team_id` on `team_id`
- `ix_scans_status` on `status`
- `ix_scans_target` on `target`

---

### findings
Security vulnerabilities and issues discovered during scans.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PK, AUTO_INCREMENT | Unique finding ID |
| scan_id | INTEGER | FK(scans.id), NOT NULL, INDEXED | Parent scan reference |
| title | VARCHAR(500) | NOT NULL | Finding title/summary |
| description | TEXT | NOT NULL | Detailed description |
| severity | VARCHAR(50) | NOT NULL, INDEXED | Severity: critical, high, medium, low, info |
| status | VARCHAR(50) | NOT NULL, INDEXED, DEFAULT 'new' | Status: new, confirmed, false_positive, etc. |
| affected_resource | VARCHAR(500) | NULLABLE | Affected host/service/resource |
| cve_id | VARCHAR(50) | NULLABLE, INDEXED | CVE identifier if applicable |
| cvss_score | FLOAT | NULLABLE | CVSS vulnerability score |
| evidence | JSONB | NULLABLE | Evidence data (screenshots, output) |
| remediation | JSONB | NULLABLE | Remediation steps and guidance |
| references | JSONB | NULLABLE | External references and links |
| tags | JSONB | NULLABLE | Custom tags for categorization |
| created_at | TIMESTAMP WITH TZ | NOT NULL, DEFAULT NOW() | Creation timestamp |
| updated_at | TIMESTAMP WITH TZ | NOT NULL, DEFAULT NOW() | Last update timestamp |

**Constraints:**
- `ON DELETE CASCADE` for scan_id foreign key

**Indexes:**
- `ix_findings_scan_id` on `scan_id`
- `ix_findings_severity` on `severity`
- `ix_findings_status` on `status`
- `ix_findings_cve_id` on `cve_id`

---

### approval_requests
Human-in-the-loop (HITL) approval workflow for sensitive operations.

| Column | Type | Constraints | Description |
|--------|------|-------------|-------------|
| id | INTEGER | PK, AUTO_INCREMENT | Unique request ID |
| scan_id | INTEGER | FK(scans.id), NOT NULL, INDEXED | Parent scan reference |
| request_type | VARCHAR(50) | NOT NULL, INDEXED | Type: tool_execution, vulnerability_scan, etc. |
| status | VARCHAR(50) | NOT NULL, INDEXED, DEFAULT 'pending' | Status: pending, approved, rejected, expired |
| title | VARCHAR(500) | NOT NULL | Request title |
| description | TEXT | NOT NULL | Detailed request description |
| risk_level | VARCHAR(50) | NOT NULL | Risk assessment: low, medium, high, critical |
| context | JSONB | NOT NULL, DEFAULT {} | Additional context data |
| requested_action | JSONB | NOT NULL | Action details to be approved |
| approved_by | INTEGER | FK(users.id), NULLABLE | User who approved/rejected |
| approved_at | TIMESTAMP WITH TZ | NULLABLE | Approval/rejection timestamp |
| rejection_reason | TEXT | NULLABLE | Reason if rejected |
| expires_at | TIMESTAMP WITH TZ | NULLABLE | Expiration time for request |
| created_at | TIMESTAMP WITH TZ | NOT NULL, DEFAULT NOW() | Creation timestamp |
| updated_at | TIMESTAMP WITH TZ | NOT NULL, DEFAULT NOW() | Last update timestamp |

**Constraints:**
- `ON DELETE CASCADE` for scan_id foreign key
- `ON DELETE SET NULL` for approved_by foreign key

**Indexes:**
- `ix_approval_requests_scan_id` on `scan_id`
- `ix_approval_requests_request_type` on `request_type`
- `ix_approval_requests_status` on `status`

## Enumerations

### TeamRole
- `owner`: Full team control
- `admin`: Administrative privileges
- `member`: Standard access
- `viewer`: Read-only access

### ScanType
- `full`: Complete recon + assessment
- `recon_only`: Reconnaissance phase only
- `assessment_only`: Assessment on existing recon data

### ScanStatus
- `pending`: Queued for execution
- `running`: Currently executing
- `completed`: Successfully finished
- `failed`: Encountered errors
- `cancelled`: Manually stopped

### FindingSeverity
- `critical`: Immediate action required
- `high`: High priority
- `medium`: Medium priority
- `low`: Low priority
- `info`: Informational only

### FindingStatus
- `new`: Newly discovered
- `confirmed`: Verified as valid
- `false_positive`: Not a real issue
- `accepted_risk`: Known and accepted
- `remediated`: Fixed/resolved
- `retest_required`: Needs verification

### ApprovalRequestType
- `tool_execution`: Security tool execution approval
- `vulnerability_scan`: Vulnerability scanning approval
- `exploit_attempt`: Exploitation attempt approval
- `data_access`: Sensitive data access approval
- `custom`: Custom approval workflow

### ApprovalStatus
- `pending`: Awaiting decision
- `approved`: Granted permission
- `rejected`: Denied permission
- `expired`: Time limit exceeded

## Migrations

Migrations are managed by Alembic:

```bash
# Create a new migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Rollback one migration
alembic downgrade -1

# Check current version
alembic current
```

## Database Connection

The application uses async SQLAlchemy with asyncpg driver:

```python
from src.db import get_db, AsyncSession
from fastapi import Depends

@app.get("/items")
async def get_items(db: AsyncSession = Depends(get_db)):
    # Use db session
    pass
```

## CRUD Operations

Use the generic CRUD base class:

```python
from src.db.crud import CRUDBase
from src.db.models import User

user_crud = CRUDBase[User, UserCreate, UserUpdate](User)

# Create
new_user = await user_crud.create(db, obj_in=user_data)

# Read
user = await user_crud.get(db, id=1)
users = await user_crud.get_multi(db, skip=0, limit=100)

# Update
updated_user = await user_crud.update(db, db_obj=user, obj_in=update_data)

# Delete
await user_crud.delete(db, id=1)
```

## Performance Considerations

1. **Indexes**: All foreign keys and frequently queried columns are indexed
2. **JSONB**: Used for flexible schema fields (config, results, evidence)
3. **Timestamps**: Automatic tracking with `created_at` and `updated_at`
4. **Connection Pooling**: Configured in `src/db/session.py`
5. **Cascading Deletes**: Properly configured to maintain referential integrity

## Backup and Maintenance

Regular database backups should be configured:

```bash
# Backup
docker exec threatweaver-postgres pg_dump -U postgres threatweaver > backup.sql

# Restore
docker exec -i threatweaver-postgres psql -U postgres threatweaver < backup.sql
```
