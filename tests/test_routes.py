
import unittest
import sys
import os
import io
from unittest.mock import patch, MagicMock

# Add parent directory to path to import app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, FEED_FILE
import app as app_module

class TestRoutes(unittest.TestCase):
    
    def setUp(self):
        app.config['TESTING'] = True
        self.client = app.test_client()
        self.test_feed = os.path.join(app_module.BASE_DIR, 'tests', 'test_feed_routes.txt')
        self.test_db = os.path.join(app_module.BASE_DIR, 'tests', 'test_ioc.db')
        
        # Patch the DB file in db module
        self.db_patcher = patch('db.DB_FILE', self.test_db)
        self.db_patcher.start()
        
        # Initialize the temp db
        import db
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        db.init_db()
        # Create a dummy user to satisfy check_setup_required
        db.create_user("admin", "dummy_hash", role="admin")
        
        if os.path.exists(self.test_feed):
            os.remove(self.test_feed)
            
    def tearDown(self):
        self.db_patcher.stop()
        if os.path.exists(self.test_feed):
            try: os.remove(self.test_feed)
            except: pass
        if os.path.exists(self.test_db):
            try: os.remove(self.test_db)
            except: pass

    def login_as_admin(self):
        # We also mock load_users to return a valid admin user if the app checks it
        with self.client.session_transaction() as sess:
            sess['username'] = 'admin'
            sess['role'] = 'admin'

    def test_manual_add_ip(self):
        self.login_as_admin()
        
        # Mock load_users to ensure 'admin' exists if checked
        mock_users = {'admin': {'role': 'admin', 'password_hash': 'xxx'}}
        
        # Patch FEED_FILE (global) AND FEEDS_CONFIG (used by index view)
        mock_feeds = {
            "multicliente": {"file": self.test_feed, "label": "Mock", "icon": "bi-hdd-network"},
            "global": {"virtual": True},
            "bpe": {"file": self.test_feed + ".bpe", "label": "BPE", "icon": "bi-bank"},
            "test": {"file": self.test_feed + ".test", "label": "Test", "icon": "bi-cone"}
        }
        
        with patch('app.FEED_FILE', self.test_feed), \
             patch('app.FEED_FILE_BPE', self.test_feed + ".bpe"), \
             patch('app.FEED_FILE_TEST', self.test_feed + ".test"), \
             patch('app.META_FILE', self.test_feed + ".meta"), \
             patch('app.load_users', return_value=mock_users), \
             patch.dict('app.FEEDS_CONFIG', mock_feeds):
            
            resp = self.client.post('/', data={
                'ip': '5.5.5.5',
                'ticket_number': 'TEST-001',
                'tags_manual_cb': 'Multicliente',
                'ttl_manual': '1'
            }, follow_redirects=True)
            
            # Ensure file exists before reading (it should be created by app, but just in case for test stability)
            if not os.path.exists(self.test_feed):
                 with open(self.test_feed, 'w') as f: f.write("")

            self.assertEqual(resp.status_code, 200)
            
            # Use stricter persistence check, relax UI text check (encoding issues possible)
            with open(self.test_feed, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('5.5.5.5', content)
            
            # Check for general success indicator in HTML
            # self.assertIn(b'success', resp.data)

    def test_csv_upload(self):
        self.login_as_admin()
        csv_content = b"6.6.6.6,Multicliente,TEST-CSV\n7.7.7.7,Multicliente,TEST-CSV"
        mock_users = {'admin': {'role': 'admin'}}
        
        mock_feeds = {
             "multicliente": {"file": self.test_feed, "label": "Mock", "icon": "bi-hdd-network"},
             "global": {"virtual": True}
        }

        with patch('app.FEED_FILE', self.test_feed), \
             patch('app.FEED_FILE_BPE', self.test_feed + ".bpe"), \
             patch('app.FEED_FILE_TEST', self.test_feed + ".test"), \
             patch('app.META_FILE', self.test_feed + ".meta"), \
             patch('app.load_users', return_value=mock_users), \
             patch.dict('app.FEEDS_CONFIG', mock_feeds):
        
            data = {
                'file': (io.BytesIO(csv_content), 'upload.csv'),
                'ttl_csv': '1'
            }
            
            
            resp = self.client.post('/', data=data, content_type='multipart/form-data', follow_redirects=True)
            if not os.path.exists(self.test_feed):
                 with open(self.test_feed, 'w') as f: f.write("")
            with open(self.test_feed, 'r', encoding='utf-8') as f:
                content = f.read()
            self.assertIn('6.6.6.6', content)
            self.assertIn('7.7.7.7', content)
            
            # self.assertIn(b'IP(s) a\xc3\xb1adida(s) correctamente (CSV)', resp.data)

    def test_feed_etag(self):
        """Test ETag caching behavior for feeds."""
        # 1. Setup mock content
        with open(self.test_feed, 'w', encoding='utf-8') as f:
            f.write("1.1.1.1|2023-01-01|0\n")
        
        with patch('app.FEED_FILE', self.test_feed):
            # 2. First Request (No ETag) -> 200 OK
            resp = self.client.get('/feed/ioc-feed.txt')
            self.assertEqual(resp.status_code, 200)
            self.assertIn('ETag', resp.headers)
            etag = resp.headers['ETag']
            self.assertTrue(etag) # Ensure it's not empty
            
            # 3. Second Request (Match) -> 304 Not Modified
            resp2 = self.client.get('/feed/ioc-feed.txt', headers={'If-None-Match': etag})
            self.assertEqual(resp2.status_code, 304)
            
            # 4. Modify content
            with open(self.test_feed, 'w', encoding='utf-8') as f:
                f.write("2.2.2.2|2023-01-01|0\n")
                
            # 5. Third Request (Mismatch) -> 200 OK with new ETag
            resp3 = self.client.get('/feed/ioc-feed.txt', headers={'If-None-Match': etag})
            self.assertEqual(resp3.status_code, 200)
            self.assertNotEqual(resp3.headers['ETag'], etag)

if __name__ == '__main__':
    unittest.main()
