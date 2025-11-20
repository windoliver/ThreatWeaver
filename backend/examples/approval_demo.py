"""
Demo: Human-in-the-Loop (HITL) Approval System

This example shows how agents can request approval for sensitive operations
like exploitation, data extraction, or destructive actions.

Usage:
    python examples/approval_demo.py
"""

import asyncio
from datetime import datetime

from src.db.models.approval import ApprovalRequestType
from src.db.session import AsyncSessionLocal
from src.services.approval import ApprovalService, create_approval_request


async def agent_requests_approval_demo():
    """
    Demo: Agent requests approval for SQLMap exploitation.

    Workflow:
    1. Agent discovers SQL injection vulnerability
    2. Agent requests human approval to extract data
    3. Approval is created with 1-hour expiry
    4. User receives notification (Slack + email)
    5. User approves/rejects via dashboard
    6. Agent proceeds or stops based on decision
    """
    print("=" * 60)
    print("DEMO: Agent Requests Approval for SQLMap Data Extraction")
    print("=" * 60)

    async with AsyncSessionLocal() as db:
        # Step 1: Agent discovers SQL injection
        print("\n[AGENT] 🔍 SQL injection detected in /api/login")
        print("[AGENT] 🎯 Target: https://api.example.com/login")
        print("[AGENT] ⚠️  CVSS Score: 8.5 (HIGH)")

        # Step 2: Agent requests approval for exploitation
        print("\n[AGENT] 🙋 Requesting human approval to extract data...")

        approval = await create_approval_request(
            db=db,
            scan_id=1,  # Assuming scan ID 1 exists
            request_type=ApprovalRequestType.EXPLOIT_ATTEMPT,
            title="SQLMap data extraction for /api/login",
            description=(
                "Execute SQLMap to extract user table from database.\n\n"
                "Vulnerability: SQL Injection (parameter: username)\n"
                "Risk: Data exposure, potential database corruption\n"
                "Recommended action: Approve only if target is authorized for exploitation"
            ),
            risk_level="HIGH",
            context={
                "target": "https://api.example.com/login",
                "vulnerability": "SQL Injection",
                "cvss_score": 8.5,
                "parameter": "username",
                "payload": "' OR '1'='1",
            },
            requested_action={
                "tool": "sqlmap",
                "parameters": [
                    "--url=https://api.example.com/login",
                    "--data=username=admin&password=test",
                    "-p", "username",
                    "--dump",
                    "-T", "users",
                ],
            },
            expiry_hours=1,
        )

        print(f"\n✅ Approval request created (ID: {approval.id})")
        print(f"   Status: {approval.status}")
        print(f"   Expires: {approval.expires_at.strftime('%Y-%m-%d %H:%M UTC')}")
        print(f"   Time remaining: 60 minutes")

        # Step 3: Notification sent (would happen in production)
        print("\n[SYSTEM] 📧 Notification sent to team:")
        print("         - Slack: #security-approvals")
        print("         - Email: security@example.com")

        # Step 4: Agent waits for approval
        print("\n[AGENT] ⏳ Waiting for human approval...")
        print("        User can approve/reject via dashboard:")
        print("        https://app.threatweaver.com/approvals/{approval.id}")

        return approval


async def user_approves_demo(approval_id: int, approve: bool):
    """
    Demo: User approves or rejects approval request.

    Args:
        approval_id: ID of the approval request
        approve: True to approve, False to reject
    """
    async with AsyncSessionLocal() as db:
        # Simulate user reviewing approval
        action = "APPROVED" if approve else "REJECTED"
        print(f"\n[USER] 👤 Reviewing approval {approval_id}...")

        # Review approval
        reviewed = await ApprovalService.review_approval(
            db=db,
            approval_id=approval_id,
            user_id=1,  # Assuming user ID 1
            approve=approve,
            rejection_reason="Too risky for production environment" if not approve else None,
        )

        print(f"\n✅ Approval {action} by user")
        print(f"   Decision: {reviewed.status}")
        print(f"   Reviewed at: {reviewed.approved_at.strftime('%Y-%m-%d %H:%M UTC')}")

        if reviewed.rejection_reason:
            print(f"   Reason: {reviewed.rejection_reason}")

        # Agent receives decision
        print(f"\n[AGENT] 📩 Decision received: {reviewed.status.upper()}")

        if approve:
            print("[AGENT] ✅ Proceeding with SQLMap data extraction...")
            print("[AGENT] 🔧 Executing: sqlmap --url=https://api.example.com/login --dump")
        else:
            print("[AGENT] ❌ Operation aborted")
            print(f"[AGENT] 📝 Reason: {reviewed.rejection_reason}")


async def auto_expiry_demo():
    """
    Demo: Approval request auto-expires after 1 hour.

    This shows what happens when a user doesn't respond in time.
    """
    print("\n" + "=" * 60)
    print("DEMO: Approval Auto-Expiry")
    print("=" * 60)

    async with AsyncSessionLocal() as db:
        # Create approval
        print("\n[AGENT] 🙋 Requesting approval...")
        approval = await create_approval_request(
            db=db,
            scan_id=1,
            request_type=ApprovalRequestType.EXPLOIT_ATTEMPT,
            title="Critical vulnerability exploitation",
            description="Execute exploit for CVE-2024-1234",
            risk_level="CRITICAL",
            context={"vulnerability": "CVE-2024-1234"},
            requested_action={"tool": "metasploit", "parameters": []},
            expiry_hours=1,
        )

        print(f"✅ Approval created (ID: {approval.id})")
        print(f"   Expires in: 1 hour")

        # Simulate time passing (in production, background task runs every 5 min)
        print("\n[SYSTEM] ⏰ Background task running (every 5 minutes)...")
        print("         Checking for expired approvals...")

        # Mark expired approvals
        expired_count = await ApprovalService.mark_expired_approvals(db)

        if expired_count > 0:
            print(f"\n[SYSTEM] 🕐 Marked {expired_count} approval(s) as EXPIRED")

            # Refresh approval to see updated status
            await db.refresh(approval)
            print(f"[AGENT] ⚠️  Approval {approval.id} expired (no response from user)")
            print("[AGENT] ❌ Operation aborted")


async def main():
    """Run all demos."""
    # Demo 1: Request approval
    approval = await agent_requests_approval_demo()

    # Demo 2: User approves
    print("\n" + "=" * 60)
    print("DEMO: User Approves Request")
    print("=" * 60)
    await user_approves_demo(approval.id, approve=True)

    # Demo 3: User rejects
    print("\n" + "=" * 60)
    print("DEMO: User Rejects Request")
    print("=" * 60)
    approval2 = await agent_requests_approval_demo()
    await user_approves_demo(approval2.id, approve=False)

    # Demo 4: Auto-expiry
    await auto_expiry_demo()

    print("\n" + "=" * 60)
    print("✅ All demos completed!")
    print("=" * 60)


if __name__ == "__main__":
    # Run demos
    asyncio.run(main())
