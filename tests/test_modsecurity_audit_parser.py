
import unittest

from parser.modsecurity_audit_parser import (
    parse_modsecurity_audit_log,
)


SAMPLE_AUDIT_LOG = '''---abc123---A--
[13/Oct/2026:11:11:11 +0530] 17918700715.324801 127.0.0.1 43100 127.0.0.1 80
---abc123---B--
GET /?id=1%20OR%201=1 HTTP/1.1
Host: 127.0.0.1
User-Agent: curl/8.20.0

---abc123---F--
HTTP/1.1 200
Server: nginx

---abc123---H--
ModSecurity: Warning. detected SQLi using libinjection. [file "/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [line "46"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [data "Matched Data: 1&1 found within ARGS:id"] [severity "2"] [uri "/"] [unique_id "abc123"]
ModSecurity: Warning. Matched "Operator `Ge'" [file "/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "81"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 8)"] [severity "2"] [uri "/"] [unique_id "abc123"]

---abc123---Z--
'''


class TestModSecurityAuditParser(unittest.TestCase):

    def test_parses_multiple_rule_messages(self):
        events = parse_modsecurity_audit_log(SAMPLE_AUDIT_LOG)

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["rule_id"], "942100")
        self.assertEqual(events[1]["rule_id"], "949110")

    def test_extracts_request_metadata(self):
        events = parse_modsecurity_audit_log(SAMPLE_AUDIT_LOG)

        self.assertEqual(events[0]["source"], "modsecurity")
        self.assertEqual(events[0]["source_ip"], "127.0.0.1")
        self.assertEqual(events[0]["method"], "GET")
        self.assertEqual(events[0]["uri"], "/?id=1%20OR%201=1")
        self.assertEqual(events[0]["status_code"], 200)

    def test_extracts_detection_message_and_severity(self):
        events = parse_modsecurity_audit_log(SAMPLE_AUDIT_LOG)

        self.assertEqual(
            events[0]["message"],
            "SQL Injection Attack Detected via libinjection",
        )
        self.assertEqual(events[0]["severity"], "HIGH")

    def test_empty_input_returns_no_events(self):
        self.assertEqual(parse_modsecurity_audit_log(""), [])


if __name__ == "__main__":
    unittest.main()
