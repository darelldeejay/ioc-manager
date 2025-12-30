
import pytest
import os
import sys
import sqlite3
import tempfile
from flask import Flask

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import db
from app import app as flask_app

@pytest.fixture
def app():
    flask_app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
    })
    
    # Create a temporary file for the database
    db_fd, db_path = tempfile.mkstemp()
    flask_app.config['DATABASE'] = db_path
    db.DB_FILE = db_path # Override db.py's global
    
    with flask_app.app_context():
        db.init_db()
        yield flask_app

    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def runner(app):
    return app.test_cli_runner()

@pytest.fixture
def test_db():
    """Provides a fresh temp database for DB logic tests without Flask app context if needed."""
    db_fd, db_path = tempfile.mkstemp()
    original_db = db.DB_FILE
    db.DB_FILE = db_path
    db.init_db()
    
    yield db
    
    db.DB_FILE = original_db
    os.close(db_fd)
    os.unlink(db_path)
