import asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text
from app.database import _database_url

async def main():
    engine = create_async_engine(_database_url)
    async with engine.begin() as conn:
        try:
            await conn.execute(text("ALTER TABLE easm_certificates ADD COLUMN is_mismatch BOOLEAN DEFAULT FALSE NOT NULL"))
            print("Column added")
        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    asyncio.run(main())
