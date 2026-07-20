import pytest
from unittest.mock import patch, AsyncMock
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient

patch("src.utils.prevention_scheduler.PreventionScheduler.start_scheduler", new_callable=AsyncMock).start()
patch("src.workers.tasks.warm_redis_cache", AsyncMock()).start()
patch("detectors.web_detector_ml.validate_web_attack_model", return_value=None).start()

from src.main import app
from src.models.models import Base
from src.api.deps import get_db

SQLALCHEMY_DATABASE_URL = "sqlite:///./test_shared.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base.metadata.create_all(bind=engine)

@pytest.fixture(scope="session")
def db_engine():
    yield engine

@pytest.fixture(scope="function")
def db():
    # Clean DB before each test
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()

@pytest.fixture(scope="function")
def client(db):
    def override_get_db():
        try:
            yield db
        finally:
            pass
            
    app.dependency_overrides[get_db] = override_get_db
    yield TestClient(app, raise_server_exceptions=False)
    app.dependency_overrides.clear()
