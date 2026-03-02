#!/usr/bin/env python3
"""Tests for NotMyRouter server pure functions."""
import unittest
import sys
from pathlib import Path

# Import functions from server.py
sys.path.insert(0, str(Path(__file__).parent))
from server import moving_average, percentile, detect_incidents, build_analysis


class TestMovingAverage(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(moving_average([], 3), [])

    def test_shorter_than_window(self):
        self.assertEqual(moving_average([1, 2], 5), [1, 2])

    def test_window_of_one(self):
        self.assertEqual(moving_average([10, 20, 30], 1), [10, 20, 30])

    def test_basic(self):
        result = moving_average([10, 20, 30, 40, 50], 3)
        self.assertEqual(len(result), 5)
        # First value is just itself
        self.assertEqual(result[0], 10.0)
        # Second value is avg of first two
        self.assertEqual(result[1], 15.0)
        # Third value is avg of [10, 20, 30]
        self.assertEqual(result[2], 20.0)
        # Fourth value is avg of [20, 30, 40]
        self.assertEqual(result[3], 30.0)

    def test_with_none_values(self):
        result = moving_average([10, None, 30], 3)
        self.assertEqual(len(result), 3)
        # None values are skipped in the average
        self.assertEqual(result[0], 10.0)
        self.assertEqual(result[1], 10.0)  # only non-None in window is 10
        self.assertEqual(result[2], 20.0)  # avg of [10, 30], skipping None

    def test_returns_new_list(self):
        original = [1, 2, 3]
        result = moving_average(original, 10)
        self.assertIsNot(result, original)


class TestPercentile(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(percentile([], 50), 0)

    def test_single_value(self):
        self.assertEqual(percentile([42.0], 50), 42.0)
        self.assertEqual(percentile([42.0], 95), 42.0)

    def test_p50(self):
        vals = list(range(1, 101))  # 1..100
        result = percentile(vals, 50)
        # int(100 * 50/100) = index 50 → value 51
        self.assertEqual(result, 51)

    def test_p95(self):
        vals = list(range(1, 101))
        result = percentile(vals, 95)
        self.assertEqual(result, 96)

    def test_p99(self):
        vals = list(range(1, 101))
        result = percentile(vals, 99)
        self.assertEqual(result, 100)

    def test_rounds_to_one_decimal(self):
        result = percentile([1.234, 2.567, 3.891], 50)
        self.assertEqual(result, 2.6)


class TestDetectIncidents(unittest.TestCase):
    def test_no_incidents(self):
        ts = ["10:00:00", "10:00:05", "10:00:10"]
        lats = [5.0, 6.0, 4.0]
        losses = [0, 0, 0]
        result = detect_incidents(ts, lats, losses, "test")
        self.assertEqual(result, [])

    def test_single_drop(self):
        ts = ["10:00:00", "10:00:05", "10:00:10"]
        lats = [5.0, 0.0, 4.0]
        losses = [0, 100, 0]
        result = detect_incidents(ts, lats, losses, "test")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["drops"], 1)
        self.assertEqual(result[0]["spikes"], 0)
        self.assertEqual(result[0]["target"], "test")

    def test_single_spike(self):
        ts = ["10:00:00", "10:00:05", "10:00:10"]
        lats = [5.0, 150.0, 4.0]
        losses = [0, 0, 0]
        result = detect_incidents(ts, lats, losses, "test")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["drops"], 0)
        self.assertEqual(result[0]["spikes"], 1)
        self.assertEqual(result[0]["max_lat"], 150.0)

    def test_consecutive_bad_grouped(self):
        ts = ["10:00:00", "10:00:05", "10:00:10", "10:00:15", "10:00:20"]
        lats = [5.0, 0.0, 200.0, 0.0, 4.0]
        losses = [0, 100, 0, 100, 0]
        result = detect_incidents(ts, lats, losses, "test")
        # Three consecutive bad samples → one incident
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["samples"], 3)
        self.assertEqual(result[0]["drops"], 2)
        self.assertEqual(result[0]["spikes"], 1)
        self.assertEqual(result[0]["start"], "10:00:05")
        self.assertEqual(result[0]["end"], "10:00:15")

    def test_separate_incidents(self):
        ts = ["10:00:00", "10:00:05", "10:00:10", "10:00:15", "10:00:20"]
        lats = [0.0, 5.0, 0.0, 5.0, 0.0]
        losses = [100, 0, 100, 0, 100]
        result = detect_incidents(ts, lats, losses, "test")
        # Good sample between each bad → separate incidents
        self.assertEqual(len(result), 3)

    def test_custom_threshold(self):
        ts = ["10:00:00", "10:00:05"]
        lats = [60.0, 60.0]
        losses = [0, 0]
        # Default threshold 100ms: no incident
        self.assertEqual(len(detect_incidents(ts, lats, losses, "t")), 0)
        # Custom threshold 50ms: incident
        self.assertEqual(len(detect_incidents(ts, lats, losses, "t", threshold_ms=50)), 1)

    def test_incident_at_end_of_data(self):
        ts = ["10:00:00", "10:00:05", "10:00:10"]
        lats = [5.0, 0.0, 0.0]
        losses = [0, 100, 100]
        result = detect_incidents(ts, lats, losses, "test")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["samples"], 2)


class TestBuildAnalysis(unittest.TestCase):
    def _make_target(self, ip, name, loss_pct=0, avg_latency=5, p50_latency=4,
                     p95_latency=8, jitter=2, total_probes=500):
        return {
            "ip": ip, "name": name, "loss_pct": loss_pct,
            "avg_latency": avg_latency, "p50_latency": p50_latency,
            "p95_latency": p95_latency, "jitter": jitter,
            "total_probes": total_probes,
        }

    def test_insufficient_data(self):
        # No router target
        targets = [self._make_target("1.1.1.1", "Cloudflare")]
        result = build_analysis(targets)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "info")
        self.assertIn("Insufficient", result[0]["title"])

    def test_router_bad(self):
        targets = [
            self._make_target("192.168.0.1", "Router", loss_pct=10),
            self._make_target("1.1.1.1", "Cloudflare", loss_pct=5),
        ]
        result = build_analysis(targets)
        severities = [f["severity"] for f in result]
        titles = [f["title"] for f in result]
        self.assertIn("critical", severities)
        self.assertTrue(any("router" in t.lower() for t in titles))

    def test_isp_bad(self):
        targets = [
            self._make_target("192.168.0.1", "Router", loss_pct=0.2),
            self._make_target("1.1.1.1", "Cloudflare", loss_pct=5),
            self._make_target("8.8.8.8", "Google", loss_pct=4),
        ]
        result = build_analysis(targets)
        severities = [f["severity"] for f in result]
        titles = [f["title"] for f in result]
        self.assertIn("critical", severities)
        self.assertTrue(any("cox" in t.lower() or "isp" in t.lower() for t in titles))

    def test_healthy(self):
        targets = [
            self._make_target("192.168.0.1", "Router", loss_pct=0),
            self._make_target("1.1.1.1", "Cloudflare", loss_pct=0),
        ]
        result = build_analysis(targets)
        severities = [f["severity"] for f in result]
        self.assertIn("ok", severities)

    def test_spiky_router_latency(self):
        targets = [
            self._make_target("192.168.0.1", "Router", loss_pct=0,
                              p50_latency=5, p95_latency=120),
            self._make_target("1.1.1.1", "Cloudflare", loss_pct=0),
        ]
        result = build_analysis(targets)
        titles = [f["title"] for f in result]
        self.assertTrue(any("spiky" in t.lower() for t in titles))

    def test_low_probe_count_warning(self):
        targets = [
            self._make_target("192.168.0.1", "Router", total_probes=50),
            self._make_target("1.1.1.1", "Cloudflare", total_probes=50),
        ]
        result = build_analysis(targets)
        titles = [f["title"] for f in result]
        self.assertTrue(any("collecting" in t.lower() or "data" in t.lower() for t in titles))

    def test_high_jitter_flagged(self):
        targets = [
            self._make_target("192.168.0.1", "Router", loss_pct=0),
            self._make_target("1.1.1.1", "Cloudflare", loss_pct=0, jitter=80),
        ]
        result = build_analysis(targets)
        titles = [f["title"] for f in result]
        self.assertTrue(any("jitter" in t.lower() for t in titles))

    def test_correlated_loss(self):
        targets = [
            self._make_target("192.168.0.1", "Router", loss_pct=0),
            self._make_target("1.1.1.1", "Cloudflare", loss_pct=3),
            self._make_target("8.8.8.8", "Google", loss_pct=2),
        ]
        result = build_analysis(targets)
        titles = [f["title"] for f in result]
        self.assertTrue(any("multiple" in t.lower() or "confirmed" in t.lower() for t in titles))


if __name__ == "__main__":
    unittest.main()
