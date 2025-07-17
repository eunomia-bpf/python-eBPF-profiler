#!/usr/bin/env python3

import sys
import os
import time
import subprocess
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from profile import BPFProfiler

class TestBPFProfiler(unittest.TestCase):
    def setUp(self):
        self.profiler = BPFProfiler()
    
    def tearDown(self):
        if hasattr(self, 'profiler') and self.profiler:
            del self.profiler
    
    def test_initialization(self):
        self.assertIsNotNone(self.profiler)
        self.assertIsNotNone(self.profiler.bpf)
        self.assertIn("do_sample", self.profiler.bpf)
    
    def test_attach_detach(self):
        pid = os.getpid()
        
        self.profiler.attach(pid)
        self.assertTrue(True)
        
        self.profiler.detach()
        self.assertTrue(True)
    
    def test_profile_simple_function(self):
        def test_function():
            total = 0
            for i in range(1000000):
                total += i
            return total
        
        pid = os.getpid()
        self.profiler.attach(pid)
        
        test_function()
        time.sleep(0.1)
        
        self.profiler.detach()
        
        profile_data = self.profiler.get_profile()
        self.assertIsInstance(profile_data, dict)
        self.assertIn("samples", profile_data)
    
    def test_profile_subprocess(self):
        test_script = """
import time
def factorial(n):
    if n <= 1:
        return 1
    return n * factorial(n - 1)

for i in range(100):
    factorial(20)
    time.sleep(0.01)
"""
        
        proc = subprocess.Popen([sys.executable, "-c", test_script])
        
        try:
            self.profiler.attach(proc.pid)
            time.sleep(1.5)
            self.profiler.detach()
            
            profile_data = self.profiler.get_profile()
            self.assertIsInstance(profile_data, dict)
            self.assertIn("samples", profile_data)
            
        finally:
            proc.terminate()
            proc.wait()
    
    def test_multiple_attach_detach(self):
        pid = os.getpid()
        
        for i in range(3):
            self.profiler.attach(pid)
            time.sleep(0.1)
            self.profiler.detach()
            
            profile_data = self.profiler.get_profile()
            self.assertIsInstance(profile_data, dict)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("Error: This test requires root privileges to run BPF programs")
        sys.exit(1)
    
    unittest.main(verbosity=2)