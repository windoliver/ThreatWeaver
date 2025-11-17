"""Simple test script to verify database operations."""

import asyncio

from sqlalchemy import select

from src.db import (
    AsyncSessionLocal,
    Finding,
    FindingSeverity,
    FindingStatus,
    Scan,
    ScanStatus,
    ScanType,
    Team,
    User,
)


async def test_database_operations() -> None:
    """Test basic CRUD operations on all models."""
    async with AsyncSessionLocal() as session:
        try:
            # Create a user
            user = User(
                email="test@example.com",
                username="testuser",
                hashed_password="fakehash123",
                full_name="Test User",
                is_active=True,
                is_superuser=False,
            )
            session.add(user)
            await session.flush()
            print(f"✓ Created user: {user}")

            # Create a team
            team = Team(
                name="Test Team",
                slug="test-team",
                description="A test team for database operations",
            )
            session.add(team)
            await session.flush()
            print(f"✓ Created team: {team}")

            # Create a scan
            scan = Scan(
                team_id=team.id,
                name="Test Scan",
                description="A test security scan",
                target="example.com",
                scan_type=ScanType.FULL.value,
                status=ScanStatus.PENDING.value,
                config={"tools": ["subfinder", "nmap"]},
            )
            session.add(scan)
            await session.flush()
            print(f"✓ Created scan: {scan}")

            # Create a finding
            finding = Finding(
                scan_id=scan.id,
                title="Test Vulnerability",
                description="A test security finding",
                severity=FindingSeverity.HIGH.value,
                status=FindingStatus.NEW.value,
                affected_resource="example.com:80",
                evidence={"port": 80, "service": "http"},
            )
            session.add(finding)
            await session.flush()
            print(f"✓ Created finding: {finding}")

            # Query operations
            result = await session.execute(select(User).where(User.email == "test@example.com"))
            queried_user = result.scalar_one_or_none()
            print(f"✓ Queried user: {queried_user}")

            result = await session.execute(select(Scan).where(Scan.team_id == team.id))
            team_scans = result.scalars().all()
            print(f"✓ Queried scans for team: {len(team_scans)} scans found")

            result = await session.execute(
                select(Finding).where(Finding.severity == FindingSeverity.HIGH.value)
            )
            high_severity_findings = result.scalars().all()
            print(f"✓ Queried high severity findings: {len(high_severity_findings)} found")

            # Update operation
            scan.status = ScanStatus.RUNNING.value
            await session.flush()
            print(f"✓ Updated scan status to: {scan.status}")

            # Commit all changes
            await session.commit()
            print("\n✅ All database operations completed successfully!")

        except Exception as e:
            await session.rollback()
            print(f"\n❌ Error during database operations: {e}")
            raise


if __name__ == "__main__":
    asyncio.run(test_database_operations())
