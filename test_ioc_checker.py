"""Offline unit test suite for Threat-Intel-IOC-Checker.

No network access and no API keys are required; the MockProvider and a
temporary SQLite file cover everything that would otherwise need live APIs.

Author : USER-Bi (Rg-Red)
Version: 1.0.0
"""
from __future__ import annotations

import json
import os
import tempfile
import time
import unittest
from pathlib import Path

from cache_manager import CacheManager, make_cache_key
from providers import (
    CLEAN,
    MALICIOUS,
    MockProvider,
    SUSPICIOUS,
    detections_to_verdict,
    score_to_verdict,
)
from validator import (
    BOGON_IP,
    IPV4,
    LOOPBACK_IP,
    MD5,
    NULL_IP,
    PRIVATE_IP,
    PUBLIC_IP,
    SHA1,
    SHA256,
    UNKNOWN,
    classify_batch,
    classify_ioc,
    classify_ip,
    dedupe,
    filter_iocs,
    is_internal_ip,
    normalize,
    refang,
)
from ioc_checker import export_json, read_iocs_from_file, resolve_ioc


class RefangNormalizeTests(unittest.TestCase):
    def test_refang_bracket_dots(self):
        self.assertEqual(refang("1[.]2[.]3[.]4"), "1.2.3.4")

    def test_refang_hxxp(self):
        self.assertEqual(refang("hxxp://evil.com"), "http://evil.com")

    def test_normalize_strips_quotes_and_whitespace(self):
        self.assertEqual(normalize('  "8.8.8.8",  '), "8.8.8.8")

    def test_normalize_empty_string(self):
        self.assertEqual(normalize(""), "")

    def test_normalize_none(self):
        self.assertEqual(normalize(None), "")


class IOCClassificationTests(unittest.TestCase):
    def test_valid_public_ipv4(self):
        record = classify_ioc("8.8.8.8")
        self.assertEqual(record.ioc_type, IPV4)
        self.assertFalse(record.is_internal)
        self.assertTrue(record.is_queryable)

    def test_valid_md5(self):
        record = classify_ioc("d41d8cd98f00b204e9800998ecf8427e")
        self.assertEqual(record.ioc_type, MD5)
        self.assertTrue(record.is_queryable)

    def test_valid_sha1(self):
        record = classify_ioc("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        self.assertEqual(record.ioc_type, SHA1)

    def test_valid_sha256(self):
        record = classify_ioc("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        self.assertEqual(record.ioc_type, SHA256)

    def test_unknown_garbage_input(self):
        record = classify_ioc("not-an-ioc-at-all")
        self.assertEqual(record.ioc_type, UNKNOWN)
        self.assertFalse(record.is_valid)

    def test_defanged_ip_classifies_as_valid(self):
        record = classify_ioc("1[.]2[.]3[.]4")
        self.assertEqual(record.ioc_type, IPV4)
        self.assertEqual(record.value, "1.2.3.4")

    def test_hash_is_lowercased(self):
        record = classify_ioc("D41D8CD98F00B204E9800998ECF8427E")
        self.assertEqual(record.value, "d41d8cd98f00b204e9800998ecf8427e")


class BogonAndPrivateFilterTests(unittest.TestCase):
    def test_rfc1918_10_range_is_internal(self):
        self.assertTrue(is_internal_ip("10.0.0.5"))

    def test_rfc1918_172_range_is_internal(self):
        self.assertTrue(is_internal_ip("172.16.0.5"))

    def test_rfc1918_192_range_is_internal(self):
        self.assertTrue(is_internal_ip("192.168.1.1"))

    def test_loopback_is_internal(self):
        tag, _ = classify_ip("127.0.0.1")
        self.assertEqual(tag, LOOPBACK_IP)
        self.assertTrue(is_internal_ip("127.0.0.1"))

    def test_null_route_is_internal(self):
        tag, _ = classify_ip("0.0.0.0")
        self.assertEqual(tag, NULL_IP)

    def test_bogon_test_net_is_internal(self):
        tag, _ = classify_ip("192.0.2.1")
        self.assertEqual(tag, BOGON_IP)

    def test_link_local_bogon(self):
        tag, _ = classify_ip("169.254.1.1")
        self.assertEqual(tag, BOGON_IP)

    def test_public_ip_is_not_internal(self):
        self.assertFalse(is_internal_ip("1.1.1.1"))
        tag, _ = classify_ip("1.1.1.1")
        self.assertEqual(tag, PUBLIC_IP)

    def test_record_marks_internal_ip_not_queryable(self):
        record = classify_ioc("192.168.0.1")
        self.assertTrue(record.is_internal)
        self.assertFalse(record.is_queryable)

    def test_filter_iocs_splits_valid_invalid(self):
        valid, invalid = filter_iocs(["8.8.8.8", "garbage", "10.0.0.1"])
        self.assertEqual(len(valid), 2)
        self.assertEqual(len(invalid), 1)

    def test_dedupe_case_insensitive(self):
        records = classify_batch(["D41D8CD98F00B204E9800998ECF8427E", "d41d8cd98f00b204e9800998ecf8427e"])
        unique = dedupe(records)
        self.assertEqual(len(unique), 1)


class CacheManagerTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.tmp_dir.name, "test_cache.db")
        self.cache = CacheManager(db_path=self.db_path, ttl_seconds=3600)

    def tearDown(self):
        self.cache.close()
        self.tmp_dir.cleanup()

    def test_cache_miss_returns_none(self):
        self.assertIsNone(self.cache.get("mock", IPV4, "8.8.8.8"))

    def test_cache_set_then_get_hits(self):
        self.cache.set("mock", IPV4, "8.8.8.8", {"verdict": CLEAN})
        entry = self.cache.get("mock", IPV4, "8.8.8.8")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.payload["verdict"], CLEAN)

    def test_cache_ttl_expiry(self):
        self.cache.set("mock", IPV4, "9.9.9.9", {"verdict": CLEAN}, ttl_seconds=0)
        time.sleep(0.05)
        self.assertIsNone(self.cache.get("mock", IPV4, "9.9.9.9"))

    def test_cache_delete(self):
        self.cache.set("mock", MD5, "a" * 32, {"verdict": MALICIOUS})
        self.cache.delete("mock", MD5, "a" * 32)
        self.assertIsNone(self.cache.get("mock", MD5, "a" * 32))

    def test_cache_purge_expired_counts_rows(self):
        self.cache.set("mock", IPV4, "1.2.3.4", {"verdict": CLEAN}, ttl_seconds=0)
        self.cache.set("mock", IPV4, "5.6.7.8", {"verdict": CLEAN}, ttl_seconds=3600)
        time.sleep(0.05)
        removed = self.cache.purge_expired()
        self.assertEqual(removed, 1)
        self.assertEqual(self.cache.count(), 1)

    def test_make_cache_key_is_deterministic(self):
        key_a = make_cache_key("MOCK", IPV4, "8.8.8.8")
        key_b = make_cache_key("mock", "ipv4", "8.8.8.8")
        self.assertEqual(key_a, key_b)


class MockProviderTests(unittest.TestCase):
    def setUp(self):
        self.provider = MockProvider()

    def test_known_malicious_ip_is_deterministic(self):
        result = self.provider.lookup("185.220.101.1", IPV4)
        self.assertEqual(result.verdict, MALICIOUS)

    def test_known_clean_ip_is_deterministic(self):
        result = self.provider.lookup("8.8.8.8", IPV4)
        self.assertEqual(result.verdict, CLEAN)

    def test_same_input_same_output(self):
        first = self.provider.lookup("203.0.113.9", IPV4)
        second = self.provider.lookup("203.0.113.9", IPV4)
        self.assertEqual(first.verdict, second.verdict)
        self.assertEqual(first.score, second.score)

    def test_hash_lookup_returns_detection_fields(self):
        result = self.provider.lookup("44d88612fea8a8f36de82e1278abb02f", MD5)
        self.assertEqual(result.verdict, MALICIOUS)
        self.assertGreater(result.total_engines, 0)


class VerdictScoringTests(unittest.TestCase):
    def test_score_to_verdict_clean_boundary(self):
        self.assertEqual(score_to_verdict(10), CLEAN)

    def test_score_to_verdict_suspicious_boundary(self):
        self.assertEqual(score_to_verdict(11), SUSPICIOUS)
        self.assertEqual(score_to_verdict(50), SUSPICIOUS)

    def test_score_to_verdict_malicious_boundary(self):
        self.assertEqual(score_to_verdict(51), MALICIOUS)

    def test_detections_to_verdict_clean(self):
        self.assertEqual(detections_to_verdict(0), CLEAN)

    def test_detections_to_verdict_suspicious(self):
        self.assertEqual(detections_to_verdict(2), SUSPICIOUS)

    def test_detections_to_verdict_malicious(self):
        self.assertEqual(detections_to_verdict(4), MALICIOUS)


class CLIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_read_iocs_from_file_skips_comments_and_blanks(self):
        file_path = Path(self.tmp_dir.name) / "iocs.txt"
        file_path.write_text("8.8.8.8\n# comment\n\n192.168.1.1\n", encoding="utf-8")
        values = read_iocs_from_file(str(file_path))
        self.assertEqual(values, ["8.8.8.8", "192.168.1.1"])

    def test_read_iocs_from_missing_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            read_iocs_from_file(str(Path(self.tmp_dir.name) / "nope.txt"))

    def test_resolve_ioc_internal_ip_skips_providers(self):
        record = classify_ioc("10.0.0.1")
        result = resolve_ioc(record, providers=[], cache=None, ttl_seconds=3600, refresh=False)
        self.assertEqual(result.provider, "local")
        self.assertIn("internal", result.detail.lower())

    def test_resolve_ioc_uses_mock_provider(self):
        from providers import build_providers

        record = classify_ioc("8.8.8.8")
        providers = build_providers(mock=True)
        result = resolve_ioc(record, providers=providers, cache=None, ttl_seconds=3600, refresh=False)
        self.assertEqual(result.provider, "mock")
        self.assertEqual(result.verdict, CLEAN)

    def test_resolve_ioc_caches_result(self):
        from providers import build_providers

        db_path = os.path.join(self.tmp_dir.name, "resolve_cache.db")
        cache = CacheManager(db_path=db_path, ttl_seconds=3600)
        record = classify_ioc("8.8.8.8")
        providers = build_providers(mock=True)

        first = resolve_ioc(record, providers, cache, ttl_seconds=3600, refresh=False)
        second = resolve_ioc(record, providers, cache, ttl_seconds=3600, refresh=False)
        cache.close()

        self.assertFalse(first.from_cache)
        self.assertTrue(second.from_cache)
        self.assertEqual(first.verdict, second.verdict)

    def test_export_json_writes_expected_structure(self):
        from providers import build_providers

        record = classify_ioc("8.8.8.8")
        providers = build_providers(mock=True)
        result = resolve_ioc(record, providers, cache=None, ttl_seconds=3600, refresh=False)

        output_path = Path(self.tmp_dir.name) / "reports" / "out.json"
        export_json(str(output_path), [(record, result)], [])

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertEqual(payload["tool"], "Threat-Intel-IOC-Checker")
        self.assertEqual(len(payload["results"]), 1)
        self.assertEqual(payload["results"][0]["value"], "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
