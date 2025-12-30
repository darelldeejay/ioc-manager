
import pytest
import json
import os
from flask import session

def test_api_summary_unauthorized(client):
    # No token provided
    resp = client.get('/api/summary')
    assert resp.status_code == 401

def test_api_summary_authorized_token(client, app):
    # Setup a valid token in temp DB
    import db
    with app.app_context():
        token = "test-secret-token"
        db.create_api_key("TestKey", token, "READ")
        
        # Test with header
        resp = client.get('/api/summary', headers={"X-API-Key": token})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data['ok'] is True
        assert 'total_ips' in data

def test_api_history_session_auth(client, app):
    # Test our recent fix: Session access allowed for UI
    with client.session_transaction() as sess:
        sess['username'] = 'admin'
        sess['role'] = 'admin'
    
    # Even without token, should work via session
    resp = client.get('/api/counters/history')
    assert resp.status_code == 200
    assert isinstance(resp.get_json(), list)

def test_api_bloquear_ip_scopes(client, app):
    import db
    with app.app_context():
        read_token = "read-only-token"
        write_token = "write-only-token"
        db.create_api_key("Read", read_token, "READ")
        db.create_api_key("Write", write_token, "WRITE")
        
        payload = {"items": [{"ip": "9.9.9.9", "tags": ["Test"], "ticket": "T-1"}]}
        
        # READ token should fail POST (Write)
        resp = client.post('/api/bloquear-ip', json=payload, headers={"X-API-Key": read_token})
        assert resp.status_code == 403 # Forbidden (Insufficient scope)
        
        # WRITE token should succeed
        resp = client.post('/api/bloquear-ip', json=payload, headers={"X-API-Key": write_token})
        assert resp.status_code == 200
