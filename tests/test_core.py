
import unittest
import sys
import os
from datetime import datetime, timedelta

# Add parent directory to path to import app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import expand_input_to_ips, is_allowed_ip, _days_left, dotted_netmask_to_prefix

class TestCoreLogic(unittest.TestCase):
    
    def test_dotted_netmask(self):
        self.assertEqual(dotted_netmask_to_prefix('255.255.255.0'), 24)
        self.assertEqual(dotted_netmask_to_prefix('255.0.0.0'), 8)
        self.assertEqual(dotted_netmask_to_prefix('255.255.255.255'), 32)
        # Invalid or non-standard masks might raise error or return None, depending on impl
        # but we stick to happy path for now

    def test_expand_input_single(self):
        self.assertEqual(expand_input_to_ips('1.1.1.1'), ['1.1.1.1'])
        self.assertEqual(expand_input_to_ips('  1.1.1.1  '), ['1.1.1.1'])

    def test_expand_input_cidr(self):
        # Use PUBLIC IP range because Private IPs are filtered out by app logic!
        # 8.8.8.0/30 -> 8.8.8.1, 8.8.8.2 (Network/Broadcast excluded normally, or handled by logic)
        ips = expand_input_to_ips('8.8.8.0/30')
        self.assertTrue(len(ips) >= 1)
        self.assertIn('8.8.8.1', ips)

    def test_expand_input_range(self):
        # Use PUBLIC IPs
        ips = expand_input_to_ips('8.8.8.1 - 8.8.8.3')
        self.assertEqual(sorted(ips), ['8.8.8.1', '8.8.8.2', '8.8.8.3'])

    def test_invalid_inputs(self):
        with self.assertRaises(ValueError):
            expand_input_to_ips('999.999.999.999')
        with self.assertRaises(ValueError):
            expand_input_to_ips('')

    def test_is_allowed_ip(self):
        # 0.0.0.0 is typically blocked
        self.assertFalse(is_allowed_ip('0.0.0.0'))
        self.assertTrue(is_allowed_ip('8.8.8.8'))

    def test_days_left(self):
        today = datetime.now()
        self.assertEqual(_days_left(today, 0), 0) # Permanent
        self.assertEqual(_days_left(today, 1), 1) # 1 day
        past = today - timedelta(days=5)
        self.assertEqual(_days_left(past, 1), 0) # Expired

if __name__ == '__main__':
    unittest.main()
