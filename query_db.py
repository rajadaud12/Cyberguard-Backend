import asyncio
import json
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from app.config import get_settings
from app.database import _database_url

async def main():
    engine = create_async_engine(_database_url)
    async with engine.begin() as conn:
        res = await conn.execute(text("SELECT hostname, issuer, valid_to, is_expired, is_mismatch FROM easm_certificates"))
        print(json.dumps([dict(row._mapping) for row in res.fetchall()]))

if __name__ == "__main__":
    asyncio.run(main())
