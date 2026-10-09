
import unittest

from parser.nginx_parser import parse_nginx_log


class TestNginxParser(unittest.TestCase):

    def test_parse_valid_access_log(self):
        log = (
            '192.168.1.50 - - '
            '[07/Oct/2026:09:22:10 +0530] '
            '"POST /login HTTP/1.1" 401 532'
        )

        result = parse_nginx_log(log)

        self.assertIsNotNone(result)
        self.assertEqual(result["source"], "nginx")
        self.assertEqual(result["event_type"], "http_request")
        self.assertEqual(result["source_ip"], "192.168.1.50")
        self.assertEqual(result["method"], "POST")
        self.assertEqual(result["uri"], "/login")
        self.assertEqual(result["status_code"], 401)
        self.assertEqual(result["severity"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
