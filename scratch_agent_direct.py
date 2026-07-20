import asyncio
from src.agent.orchestrator import SecurityAgent
from src.core.database import SessionLocal

async def main():
    agent = SecurityAgent(tenant_id="test_tenant")
    
    # 1. URL
    try:
        res = await agent.analyze("url", "http://secure-login-paypal-update.com/login")
        print("URL:", res)
    except Exception as e:
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
