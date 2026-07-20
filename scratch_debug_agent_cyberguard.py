import asyncio
import uuid
from src.api.v1.agent import agent_analyze, AgentAnalyzeRequest
from src.api.deps import AuthContext
from src.models.models import Workspace, User
from src.core.database import SessionLocal

async def main():
    db = SessionLocal()
    ws = db.query(Workspace).first()
    if not ws:
        print("No workspace found")
        return

    request = AgentAnalyzeRequest(type="url", data="http://secure-login-paypal-update.com/login")
    auth = AuthContext(workspace=ws, user=None)

    try:
        res = await agent_analyze(request, db, auth)
        print("SUCCESS")
    except Exception as e:
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(main())
