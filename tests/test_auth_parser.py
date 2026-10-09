
import unittest

from parser.auth_parser import parse_auth_log


class TestAuthParser(unittest.TestCase):

    def test_parse_failed_login(self):
        log = (
            "Oct  7 09:31:15 server sshd[1235]: "
            "Failed password for admin from "
            "192.168.1.50 port 52145 ssh2"
        )

        result = parse_auth_log(log)

        self.assertIsNotNone(result)
        self.assertEqual(result["source"], "linux_auth")
        self.assertEqual(
            result["event_type"], "authentication_failure"
        )
        self.assertEqual(result["source_ip"], "192.168.1.50")
        self.assertEqual(result["username"], "admin")
        self.assertEqual(result["action"], "failed")
        self.assertEqual(result["severity"], "MEDIUM")

    def test_parse_successful_login(self):
        log = (
            "Oct  7 09:31:20 server sshd[1235]: "
            "Accepted password for mrunal from "
            "192.168.1.10 port 52146 ssh2"
        )

        result = parse_auth_log(log)

        self.assertIsNotNone(result)
        self.assertEqual(
            result["event_type"], "authentication_success"
        )
        self.assertEqual(result["source_ip"], "192.168.1.10")
        self.assertEqual(result["username"], "mrunal")
        self.assertEqual(result["action"], "accepted")
        self.assertEqual(result["severity"], "LOW")

    def test_ignore_unmatched_log(self):
        log = "This is not a valid SSH authentication log"

        result = parse_auth_log(log)

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
