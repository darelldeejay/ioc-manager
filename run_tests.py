
import unittest
import sys
import os

if __name__ == '__main__':
    # Discover and run tests
    start_dir = os.path.join(os.path.dirname(__file__), 'tests')
    loader = unittest.TestLoader()
    suite = loader.discover(start_dir)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    sys.exit(not result.wasSuccessful())
