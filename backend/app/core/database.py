"""Database configuration and connection."""

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# SQLite database URL - creates file in backend directory
DATABASE_URL = "sqlite:///./phishcheck.db"

# Create engine with SQLite-specific settings
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}  # Needed for SQLite
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


def get_db():
    """Dependency that provides a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Initialize the database, creating all tables."""
    # Import models to ensure they're registered with Base
    from app.models.user import User, Session  # noqa: F401
    
    # Create all tables
    Base.metadata.create_all(bind=engine)
