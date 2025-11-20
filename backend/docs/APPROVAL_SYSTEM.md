# Human-in-the-Loop (HITL) Approval System

## Overview

The HITL Approval System provides a secure, database-backed workflow for obtaining human approval before executing sensitive operations like exploitation, data extraction, or destructive actions.

**Key Features:**
- ✅ Database-backed approval requests with 1-hour auto-expiry
- ✅ Real-time notifications (Slack + Email)
- ✅ RESTful API for approval management
- ✅ Automatic expiration of pending approvals
- ✅ Rich context and metadata for informed decisions
- ✅ Background task for auto-expiry

**Architecture Reference:** architecture.md Section 9 (Human-in-Loop for Exploitation)

---

## Quick Start

### 1. Agent Requests Approval

```python
from src.services.approval import create_approval_request
from src.db.models.approval import ApprovalRequestType

# Agent discovers SQL injection and requests approval
approval = await create_approval_request(
    db=db,
    scan_id=123,
    request_type=ApprovalRequestType.EXPLOIT_ATTEMPT,
    title="SQLMap data extraction for /api/login",
    description="Execute SQLMap to extract user table from database",
    risk_level="HIGH",
    context={
        "target": "https://api.example.com/login",
        "vulnerability": "SQL Injection",
        "cvss_score": 8.5,
    },
    requested_action={
        "tool": "sqlmap",
        "parameters": ["--dump", "-T", "users"],
    },
    expiry_hours=1,  # Auto-expire after 1 hour
)

print(f"Approval request created: {approval.id}")
print(f"Status: {approval.status}")  # "pending"
print(f"Expires: {approval.expires_at}")
```

### 2. User Reviews Approval

**Via API:**
```bash
# Get pending approvals
curl -X GET "http://localhost:8000/api/v1/approvals/pending" \
  -H "Authorization: Bearer <token>"

# Approve request
curl -X POST "http://localhost:8000/api/v1/approvals/456/review" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "approve": true
  }'

# Reject request
curl -X POST "http://localhost:8000/api/v1/approvals/456/review" \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "approve": false,
    "rejection_reason": "Too risky for production"
  }'
```

**Via Python:**
```python
from src.services.approval import review_approval

# Approve
approved = await review_approval(
    db=db,
    approval_id=456,
    user_id=1,
    approve=True,
)

# Reject
rejected = await review_approval(
    db=db,
    approval_id=457,
    user_id=1,
    approve=False,
    rejection_reason="Too risky for production",
)
```

### 3. Agent Checks Decision

```python
from src.services.approval import get_approval_request, ApprovalService

# Get approval status
approval = await get_approval_request(db, approval_id=456)

if ApprovalService.is_approved(approval):
    # Proceed with exploitation
    print("✅ Approved! Executing SQLMap...")
    execute_sqlmap(approval.requested_action)

elif approval.status == "rejected":
    # Stop and log reason
    print(f"❌ Rejected: {approval.rejection_reason}")
    abort_operation()

elif ApprovalService.is_expired(approval):
    # Auto-expired after 1 hour
    print("⏰ Approval expired. Aborting operation.")
    abort_operation()
```

---

## API Endpoints

### POST /api/v1/approvals
Create a new approval request.

**Request:**
```json
{
  "scan_id": 123,
  "request_type": "exploit_attempt",
  "title": "SQLMap data extraction for /api/login",
  "description": "Execute SQLMap to extract user table from database",
  "risk_level": "HIGH",
  "context": {
    "target": "https://api.example.com/login",
    "vulnerability": "SQL Injection",
    "cvss_score": 8.5
  },
  "requested_action": {
    "tool": "sqlmap",
    "parameters": ["--dump", "-T", "users"]
  },
  "expiry_hours": 1
}
```

**Response:**
```json
{
  "id": 456,
  "scan_id": 123,
  "request_type": "exploit_attempt",
  "status": "pending",
  "title": "SQLMap data extraction for /api/login",
  "description": "Execute SQLMap to extract user table from database",
  "risk_level": "HIGH",
  "context": {...},
  "requested_action": {...},
  "approved_by": null,
  "approved_at": null,
  "rejection_reason": null,
  "expires_at": "2025-11-19T23:59:00Z",
  "created_at": "2025-11-19T22:59:00Z",
  "updated_at": "2025-11-19T22:59:00Z",
  "is_expired": false,
  "time_remaining_minutes": 55
}
```

### GET /api/v1/approvals/pending
Get all pending approvals for the current user's team.

**Response:**
```json
{
  "approvals": [
    {
      "id": 456,
      "status": "pending",
      "title": "SQLMap data extraction",
      ...
    }
  ],
  "total": 1
}
```

### GET /api/v1/approvals/{id}
Get details of a specific approval request.

### POST /api/v1/approvals/{id}/review
Approve or reject an approval request.

**Request:**
```json
{
  "approve": true,
  "rejection_reason": null
}
```

**Response:**
```json
{
  "id": 456,
  "status": "approved",
  "approved_by": 1,
  "approved_at": "2025-11-19T23:15:00Z",
  ...
}
```

---

## Approval Request Types

```python
class ApprovalRequestType(str, Enum):
    TOOL_EXECUTION = "tool_execution"          # Generic tool execution
    VULNERABILITY_SCAN = "vulnerability_scan"  # Vulnerability scanning
    EXPLOIT_ATTEMPT = "exploit_attempt"        # Exploitation (SQLMap, Metasploit)
    DATA_ACCESS = "data_access"                # Access to sensitive data
    CUSTOM = "custom"                          # Custom approval
```

## Risk Levels

- `LOW`: Minimal risk, read-only operations
- `MEDIUM`: Moderate risk, reversible actions
- `HIGH`: High risk, data extraction, exploitation
- `CRITICAL`: Critical risk, destructive operations, shell access

---

## Auto-Expiry System

Pending approval requests automatically expire after the specified time (default: 1 hour).

**Background Task:**
```python
# Run background task to mark expired approvals
from src.services.tasks import mark_expired_approvals_task

# Runs every 5 minutes
await mark_expired_approvals_task()
```

**Start Background Scheduler:**
```bash
# Run scheduler in separate process
python -m src.services.tasks
```

**Production Setup (APScheduler example):**
```python
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from src.services.tasks import mark_expired_approvals_task

scheduler = AsyncIOScheduler()
scheduler.add_job(
    mark_expired_approvals_task,
    'interval',
    minutes=5,
    id='mark_expired_approvals',
)
scheduler.start()
```

---

## Notifications

### Slack Notifications

Set `SLACK_WEBHOOK_URL` environment variable:

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX"
```

**Send notification:**
```python
from src.services.notifications import send_approval_notification

# Automatically sends Slack notification
await send_approval_notification(
    approval=approval,
    slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL"),
)
```

**Slack Message Format:**
```
🔔 New Approval Request: SQLMap data extraction for /api/login

Type: exploit_attempt
Risk Level: HIGH
Scan ID: 123
Expires: 2025-11-19 23:59 UTC

Description:
Execute SQLMap to extract user table from database

[Review in Dashboard] (button)
```

### Email Notifications (TODO)

Email notifications are planned for future implementation.

---

## Database Schema

```sql
CREATE TABLE approval_requests (
    id SERIAL PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    request_type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    risk_level VARCHAR(50) NOT NULL,
    context JSONB NOT NULL,
    requested_action JSONB NOT NULL,
    approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    approved_at TIMESTAMP WITH TIME ZONE,
    rejection_reason TEXT,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX ix_approval_requests_scan_id ON approval_requests(scan_id);
CREATE INDEX ix_approval_requests_status ON approval_requests(status);
CREATE INDEX ix_approval_requests_request_type ON approval_requests(request_type);
```

---

## Testing

Run tests:
```bash
pytest tests/test_approvals.py -v
```

**Test Coverage:**
- ✅ Create approval request
- ✅ Get approval by ID
- ✅ Get pending approvals for team
- ✅ Approve approval request
- ✅ Reject approval request
- ✅ Prevent double-review
- ✅ Prevent reviewing expired approvals
- ✅ Auto-expire pending approvals
- ✅ Helper functions (is_approved, is_expired)

---

## Integration with Agents

### LangGraph Integration

```python
from langgraph.graph import StateGraph
from src.services.approval import create_approval_request, ApprovalService

def request_exploitation_approval(state):
    """LangGraph node to request approval before exploitation."""

    # Create approval request
    approval = await create_approval_request(
        db=db,
        scan_id=state["scan_id"],
        request_type=ApprovalRequestType.EXPLOIT_ATTEMPT,
        title=f"Exploit {state['vulnerability']['name']}",
        description=state["exploitation_plan"],
        risk_level=state["vulnerability"]["severity"],
        context=state["vulnerability"],
        requested_action=state["exploitation_command"],
    )

    # Wait for approval (polling or callback)
    while True:
        await asyncio.sleep(30)  # Check every 30 seconds

        approval = await get_approval_request(db, approval.id)

        if ApprovalService.is_approved(approval):
            state["approval_status"] = "approved"
            break
        elif approval.status in ["rejected", "expired"]:
            state["approval_status"] = approval.status
            state["rejection_reason"] = approval.rejection_reason
            break

    return state

# Add to LangGraph workflow
workflow = StateGraph(...)
workflow.add_node("request_approval", request_exploitation_approval)
workflow.add_edge("vulnerability_found", "request_approval")
workflow.add_conditional_edges(
    "request_approval",
    lambda s: "exploit" if s["approval_status"] == "approved" else "report",
)
```

---

## Security Considerations

1. **Authorization**: Only team members can review approvals for their team's scans
2. **Expiry**: All approvals auto-expire (default: 1 hour) to prevent stale requests
3. **Audit Trail**: All approvals are logged with timestamps and user IDs
4. **Risk Assessment**: Each request includes risk level and detailed context
5. **Immutability**: Approved/rejected requests cannot be changed

---

## Future Enhancements

- [ ] Email notifications
- [ ] Real-time updates via WebSockets/SSE
- [ ] Approval delegation (assign to specific users)
- [ ] Approval workflows (multi-stage approvals)
- [ ] Integration with Slack interactive buttons
- [ ] Dashboard notification badge
- [ ] Approval analytics and metrics

---

## Related Files

- **Models**: `src/db/models/approval.py`
- **Services**: `src/services/approval.py`, `src/services/notifications.py`, `src/services/tasks.py`
- **API**: `src/api/v1/approvals.py`, `src/api/schemas/approval.py`
- **Tests**: `tests/test_approvals.py`
- **Examples**: `examples/approval_demo.py`
- **Migration**: `alembic/versions/9c15d24eda91_add_approval_requests_table.py`

---

## Support

For questions or issues, see:
- GitHub Issues: https://github.com/windoliver/ThreatWeaver/issues
- Architecture Doc: architecture.md Section 9
