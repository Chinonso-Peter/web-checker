import os

import sqlalchemy as sa
from sqlalchemy import text as sa_text

from backend import db
from backend.config import Config


def init_db(app):
    """
    Database Connection and Schema Initialization.
    
    Bootstraps the application data storage:
    1. Resolves the filesystem path for the SQLite database file from configuration.
    2. Ensures parent directories exist on the host filesystem.
    3. Executes SQLAlchemy db.create_all() within Flask application context to create tables.
    4. Applies automated, non-destructive schema migrations for newly introduced columns.
    
    Returns:
        str: Absolute path to the initialized database file.
    """
    path = app.config["DATABASE_PATH"]
    # Step 1: Ensure directory structure exists on disk
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    # Step 2: Bind database operations within application context
    with app.app_context():
        # Create all tables declared in models (users, scans)
        db.create_all()
        # Apply versioned incremental schema migrations
        _migrate(app)
    return path


def _migrate(app):
    """
    Lightweight Database Schema Migration Engine.
    
    Inspects existing database tables and dynamically applies ALTER TABLE statements
    for any newly introduced columns, preserving existing production/test data without
    requiring external migration tooling (e.g. Alembic).
    """
    inspector = sa.inspect(db.engine)
    
    # Check and upgrade 'scans' table columns
    if "scans" in inspector.get_table_names():
        columns = {c["name"] for c in inspector.get_columns("scans")}
        if "parameters" not in columns:
            db.session.execute(
                sa_text("ALTER TABLE scans ADD COLUMN parameters TEXT")
            )
            db.session.commit()
        if "cookies" not in columns:
            db.session.execute(
                sa_text("ALTER TABLE scans ADD COLUMN cookies TEXT")
            )
            db.session.commit()
        if "headers" not in columns:
            db.session.execute(
                sa_text("ALTER TABLE scans ADD COLUMN headers TEXT")
            )
            db.session.commit()

    # Check and upgrade 'users' table columns
    if "users" in inspector.get_table_names():
        columns = {c["name"] for c in inspector.get_columns("users")}
        if "reset_token" not in columns:
            db.session.execute(
                sa_text("ALTER TABLE users ADD COLUMN reset_token VARCHAR(64) DEFAULT NULL")
            )
            db.session.commit()
            # Add unique index separately (SQLite doesn't support ADD COLUMN with UNIQUE)
            db.session.execute(
                sa_text("CREATE UNIQUE INDEX idx_users_reset_token ON users(reset_token)")
            )
            db.session.commit()
        if "reset_token_expires" not in columns:
            db.session.execute(
                sa_text("ALTER TABLE users ADD COLUMN reset_token_expires TIMESTAMP DEFAULT NULL")
            )
            db.session.commit()
        if "is_verified" not in columns:
            db.session.execute(
                sa_text("ALTER TABLE users ADD COLUMN is_verified BOOLEAN DEFAULT 0")
            )
            db.session.commit()
        if "verification_token" not in columns:
            db.session.execute(
                sa_text("ALTER TABLE users ADD COLUMN verification_token VARCHAR(64) DEFAULT NULL")
            )
            db.session.commit()
            db.session.execute(
                sa_text("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_verification_token ON users(verification_token)")
            )
            db.session.commit()
        if "verification_token_expires" not in columns:
            db.session.execute(
                sa_text("ALTER TABLE users ADD COLUMN verification_token_expires TIMESTAMP DEFAULT NULL")
            )
            db.session.commit()