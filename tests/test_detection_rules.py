
import unittest

from detection.detection_engine import (
    detect_brute_force,
    detect_sql_injection,
    detect_xss
)


class TestDetectionRules(unittest.TestCase):

    def test_brute_force_detection(self):
        events = [
            {
                "event_type": "authentication_failure",
                "source_ip": "192.168.1.50"
            }
            for _ in range(3)
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["alert_type"],
            "BRUTE_FORCE_SUSPECTED"
        )
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["risk_score"], 75)
    
    def test_brute_force_below_threshold(self):
        events = [
            {
                "event_type": "authentication_failure",
                "source_ip": "192.168.1.50"
            }
            for _ in range(2)
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)


    def test_sql_injection_detection(self):
        events = [{
            "event_type": "waf_blocked",
            "source_ip": "192.168.1.50",
            "rule_id": "942100",
            "uri": "/search",
            "message": "SQL Injection detected"
        }]

        alerts = detect_sql_injection(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["alert_type"],
            "SQL_INJECTION_DETECTED"
        )
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["risk_score"], 75)

    
    def test_sql_injection_ignores_normal_events(self):
        events = [
            {
                "event_type": "http_request",
                "source_ip": "192.168.1.20",
                "rule_id": None,
                "uri": "/products",
                "message": "Normal request"
            },
            {
                "event_type": "waf_blocked",
                "source_ip": "192.168.1.30",
                "rule_id": "941100",
                "uri": "/search",
                "message": "XSS Attack detected"
            }
        ]

        alerts = detect_sql_injection(events)

        self.assertEqual(len(alerts), 0)


    def test_xss_detection(self):
        events = [{
            "event_type": "waf_blocked",
            "source_ip": "192.168.1.60",
            "rule_id": "941100",
            "uri": "/search",
            "message": "XSS Attack detected"
        }]

        alerts = detect_xss(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(
            alerts[0]["alert_type"],
            "XSS_DETECTED"
        )
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["risk_score"], 75)

    
    def test_xss_ignores_unrelated_events(self):
        events = [
            {
                "event_type": "http_request",
                "source_ip": "192.168.1.20",
                "rule_id": None,
                "uri": "/products",
                "message": "Normal request"
            },
            {
                "event_type": "waf_blocked",
                "source_ip": "192.168.1.50",
                "rule_id": "942100",
                "uri": "/search",
                "message": "SQL Injection detected"
            }
        ]

        alerts = detect_xss(events)

        self.assertEqual(len(alerts), 0)

    
    def test_brute_force_ignores_unrelated_events(self):
        events = [
            {
                "event_type": "http_request",
                "source_ip": "192.168.1.20"
            },
            {
                "event_type": "waf_blocked",
                "source_ip": "192.168.1.50"
            }
        ]

        alerts = detect_brute_force(events)

        self.assertEqual(len(alerts), 0)




if __name__ == "__main__":
    unittest.main()
