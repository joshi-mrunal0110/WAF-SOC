
import unittest

from parser.waf_parser import parse_waf_log


class TestWAFParser(unittest.TestCase):

    def test_parse_blocked_request(self):
        log = (
            '2026-10-07 09:40:10 192.168.1.50 '
            '"GET /search?q=\' OR 1=1--" '
            '"SQL Injection detected" "942100"'
        )

        result = parse_waf_log(log)

        self.assertIsNotNone(result)
        self.assertEqual(result["source"], "waf")
        self.assertEqual(result["event_type"], "waf_blocked")
        self.assertEqual(result["source_ip"], "192.168.1.50")
        self.assertEqual(result["action"], "blocked")
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["uri"], "/search?q=' OR 1=1--")
        self.assertEqual(result["rule_id"], "942100")
        self.assertEqual(result["severity"], "HIGH")

    def test_parse_allowed_request(self):
        log = (
            '2026-10-07 09:42:05 192.168.1.70 '
            '"GET /admin" '
            '"Request allowed" "-"'
        )

        result = parse_waf_log(log)

        self.assertIsNotNone(result)
        self.assertEqual(result["event_type"], "waf_allowed")
        self.assertEqual(result["source_ip"], "192.168.1.70")
        self.assertEqual(result["action"], "allowed")
        self.assertEqual(result["method"], "GET")
        self.assertEqual(result["uri"], "/admin")
        self.assertIsNone(result["rule_id"])
        self.assertEqual(result["severity"], "LOW")

    def test_ignore_invalid_log(self):
        log = "This is not a valid WAF log"

        result = parse_waf_log(log)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
