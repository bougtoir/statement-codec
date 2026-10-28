"""unittest-discoverable suite for v16 (python -m unittest works)."""
import json, subprocess, sys, unittest

def run(script):
    r = subprocess.run([sys.executable, script], capture_output=True, text=True)
    return r.returncode, r.stdout, r.stderr

class ParitySuite(unittest.TestCase):
    def test_comp2_parity_equivalence(self):
        rc, out, err = run("bench_v16.py")
        self.assertEqual(rc, 0, err)
        d = json.loads(out)
        # expectation: comp2 reaches same labels on all T1 cases
        self.assertTrue(d["equivalent_labels"])
        self.assertEqual(len(d["T1"]), 18)
    def test_codec_benchmark(self):
        rc, out, err = run("bench_v12.py")
        self.assertEqual(rc, 0, err)
        d = json.loads(out)
        self.assertEqual(d["T1"]["codec"]["accuracy"], 1.0)
        self.assertTrue(d["T3"]["all_detected"])
    def test_intentional_failure_detected(self):
        # sanity: a deliberately wrong assertion must fail (nonzero exit)
        code = "import unittest\nclass T(unittest.TestCase):\n def test_x(self): self.assertTrue(False)\n"
        open("_tf.py","w").write(code)
        r = subprocess.run([sys.executable,"-m","unittest","_tf","-q"],capture_output=True,text=True)
        self.assertNotEqual(r.returncode, 0)
if __name__ == "__main__":
    unittest.main()
