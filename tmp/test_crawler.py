import asyncio
import sys
import os

# Add backend to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.services.easm_scanner import _crawl_links

async def main():
    paths = await _crawl_links('http://127.0.0.1:3003/')
    print("Crawled Paths:")
    for p in sorted(list(paths)):
        print(p)

if __name__ == "__main__":
    asyncio.run(main())
