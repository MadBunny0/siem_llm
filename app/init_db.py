"""Initialize the PostgreSQL schema before the API container starts."""

from app.db import Base, engine
from app import models  # noqa: F401 - registers all SQLAlchemy models


def main() -> None:
    Base.metadata.create_all(bind=engine)
    print("Database schema initialized successfully.", flush=True)


if __name__ == "__main__":
    main()
