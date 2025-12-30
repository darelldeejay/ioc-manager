
import pytest
import json

def test_user_management(test_db):
    # Initial count
    assert test_db.get_user_count() == 0
    
    # Create user
    test_db.create_user("johndoe", "hashed_pwd", role="admin")
    assert test_db.get_user_count() == 1
    
    # Verify user
    user = test_db.get_user_by_username("johndoe")
    assert user['username'] == "johndoe"
    assert user['role'] == "admin"

def test_ip_metadata(test_db):
    ip = "1.2.3.4"
    tags = ["Multicliente", "Test"]
    
    # Add IP (upsert_ip takes more args)
    test_db.upsert_ip(ip, source="manual", tags=tags, ttl="7", expiration_date=None, alert_ids=[], history=[])
    
    # Get IP details
    details = test_db.get_ip(ip)
    assert details is not None
    assert details['source'] == "manual"
    assert "Multicliente" in json.loads(details['tags'])
    
    # Remove tag
    test_db.remove_tag(ip, "Test")
    details = test_db.get_ip(ip)
    assert "Test" not in json.loads(details['tags'])
    assert "Multicliente" in json.loads(details['tags'])
    
    # Remove IP
    test_db.delete_ip(ip)
    assert test_db.get_ip(ip) is None

def test_metrics_history(test_db):
    # Save snapshot
    snapshot = {'total': 50, 'manual': 10, 'csv': 30, 'api': 10, 'tags': {'BPE': 5}}
    test_db.save_daily_snapshot(snapshot)
    
    # Retrieve
    history = test_db.get_metrics_history(limit=5)
    assert len(history) == 1
    assert history[0]['total'] == 50
    assert history[0]['sources']['manual'] == 10

def test_api_keys(test_db):
    name = "ExternalMonitor"
    token = "xyz-123"
    scopes = "READ"
    
    # Add key
    test_db.create_api_key(name, token, scopes)
    
    # Verify
    key = test_db.get_api_key(token)
    assert key is not None
    assert key['name'] == name
    assert key['scopes'] == "READ"
