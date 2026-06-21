import asyncio
from app.services.verification_engine import NucleiVerificationEngine
async def main():
    engine = NucleiVerificationEngine()
    phase3_tags = 'dast,sqli,xss,ssti,lfi,rce,injection,idor,redirect'
    paths = engine._find_matching_templates(['dast'], phase3_tags)
    print(f'Found {len(paths)} templates for phase 3')
    res = await engine._run_nuclei_batch(['http://127.0.0.1:3003'], phase3_tags, paths, is_dast=True)
    print(f'Phase 3 found {len(res)} results')
    for r in res:
        print(f"- {r.get('template_id')}")
asyncio.run(main())
