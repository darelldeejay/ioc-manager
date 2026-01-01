
import unittest
import sys
import os
import json
from unittest.mock import patch, MagicMock

# Add parent directory to path to import app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app
import app as app_module

class TestAPI(unittest.TestCase):
    
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        self.test_feed = os.path.join(app_module.BASE_DIR, 'tests', 'test_feed_api.txt')
        self.test_db = os.path.join(app_module.BASE_DIR, 'tests', 'test_api.db')
        self.test_log = os.path.join(app_module.BASE_DIR, 'tests', 'test_api_audit.jsonl')

        # === DB ISOLATION ===
        self.db_patcher = patch('db.DB_FILE', self.test_db)
        self.db_patcher.start()
        
        # Init temp DB
        import db
        if os.path.exists(self.test_db):
            try: os.remove(self.test_db)
            except: pass
        db.init_db()

        # === FILES ISOLATION ===
        self.feed_patcher = patch('app.FEED_FILE', self.test_feed)
        self.bpe_patcher = patch('app.FEED_FILE_BPE', self.test_feed + ".bpe")
        self.test_feed_patcher = patch('app.FEED_FILE_TEST', self.test_feed + ".test")
        self.meta_patcher = patch('app.META_FILE', self.test_feed + ".meta")
        self.audit_patcher = patch('app.AUDIT_LOG_FILE', self.test_log)
        
        self.feed_patcher.start()
        self.bpe_patcher.start()
        self.test_feed_patcher.start()
        self.meta_patcher.start()
        self.audit_patcher.start()
        
        self._clean_files()

    def tearDown(self):
        self.db_patcher.stop()
        self.feed_patcher.stop()
        self.bpe_patcher.stop()
        self.test_feed_patcher.stop()
        self.meta_patcher.stop()
        self.audit_patcher.stop()
        
        self._clean_files()
        if os.path.exists(self.test_db):
            try: os.remove(self.test_db)
            except: pass
        if os.path.exists(self.test_log):
            try: os.remove(self.test_log)
            except: pass

    def _clean_files(self):
        for ext in ["", ".bpe", ".test", ".meta", ".lock"]:
            f = self.test_feed + ext
            if os.path.exists(f):
                try:
                    os.remove(f)
                except:
                    pass
        # Clean tags dir if possible
        tags_dir = os.path.join(os.path.dirname(self.test_feed), "tags")
        import shutil
        if os.path.exists(tags_dir):
            try:
                shutil.rmtree(tags_dir)
            except:
                pass

    def test_api_unauthorized(self):
        # Without any patch, TOKEN_API might be None or Env.
        # But we want to fail if token provided is wrong.
        # Patch TOKEN_API to 'secret'
        with patch('app.TOKEN_API', 'secret'):
             resp = self.client.post('/api/bloquear-ip', json={})
             self.assertEqual(resp.status_code, 401)

    def test_api_authorized_add(self):
        # Patch TOKEN_API and ALL FEED FILES to be safe
        # Use simple temp names
        base = self.test_feed
        
        with patch('app.TOKEN_API', 'test-token'), \
             patch('app.TAGS_DIR', os.path.join(os.path.dirname(base), "tags")):
            
            # Ensure cleanup of these extra files if needed, or let OS temp handle (but we use local file)
            # setUp/tearDown only cleans self.test_feed.
            # Ideally use tempfile module, but sticking to simple path for now.
            
            headers = {'X-API-Key': 'test-token'}
            # Add 'Multicliente' to ensure it goes to FEED_FILE
            payload = {
                "items": [
                    {"ip": "8.8.4.4", "tags": ["Test", "Multicliente"], "ttl": "1"}
                ]
            }
            resp = self.client.post('/api/bloquear-ip', json=payload, headers=headers)
            self.assertEqual(resp.status_code, 200)
            
            # Verify persistence in Main Feed
            with open(base, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('8.8.4.4', content)

    def test_api_idempotency(self):
        base = self.test_feed
        with patch('app.TOKEN_API', 'test-token'):
             
            headers = {'X-API-Key': 'test-token'}
            payload = {
                "items": [
                    {"ip": "1.2.3.4", "tags": ["Test", "Multicliente"], "ttl": "1"}
                ]
            }
            # First hit
            self.client.post('/api/bloquear-ip', json=payload, headers=headers)
            
            # Second hit (Duplicate)
            resp = self.client.post('/api/bloquear-ip', json=payload, headers=headers)
            self.assertEqual(resp.status_code, 200)
            data = json.loads(resp.data)
            self.assertEqual(data['status'], 'ok')
            self.assertEqual(data['processed'][0]['count'], 1)

if __name__ == '__main__':
    unittest.main()
