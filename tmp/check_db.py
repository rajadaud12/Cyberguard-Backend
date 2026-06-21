import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import AsyncSessionLocal
from app.models.finding import Finding
from sqlalchemy import select

async def main():
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(Finding).where(Finding.issue_type.like("Exposed Sensitive File: Config/Backup%")))
        findings = result.scalars().all()
        for f in findings:
            print(f.issue_type, f.evidence.get("url"))

if __name__ == "__main__":
    asyncio.run(main())
