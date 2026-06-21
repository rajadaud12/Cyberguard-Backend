import asyncio
import logging
from app.services.verification_engine import NucleiVerificationEngine

logging.basicConfig(level=logging.DEBUG)

async def main():
    engine = NucleiVerificationEngine()
    print("Testing DAST on /api/Products")
    targets = ["http://127.0.0.1:3003/api/Products"]
    results = await engine.verify(targets, tags=[])
    for r in results:
        print(f"[{r.get('severity', 'info').upper()}] {r.get('template_id')} - {r.get('matched_at')}")
    print("Found", len(results), "vulnerabilities")

if __name__ == "__main__":
    asyncio.run(main())
