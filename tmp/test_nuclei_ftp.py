import asyncio
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.services.verification_engine import NucleiVerificationEngine

async def main():
    e = NucleiVerificationEngine()
    res = await e.verify(["http://127.0.0.1:3003/ftp/"], tags=["exposure","config","backup","misconfig"])
    for r in res:
        print(f"[{r.get('severity', 'info').upper()}] {r.get('template_id')} - {r.get('matched_at')}")

if __name__ == "__main__":
    asyncio.run(main())
