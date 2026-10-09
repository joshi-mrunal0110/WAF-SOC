from collections import defaultdict

SEVERITY_SCORES = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 100
}

def get_risk_score(severity):
    return SEVERITY_SCORES.get(severity, 0)

def detect_brute_force(events, threshold=3):
    failed_attempts = defaultdict(list)
    alerts = []

    for event in events:
        if event["event_type"] == "authentication_failure":
            ip = event["source_ip"]
            failed_attempts[ip].append(event)

    for ip, attempts in failed_attempts.items():
        if len(attempts) >= threshold:
           alerts.append({
                "alert_type": "BRUTE_FORCE_SUSPECTED",
                "severity": "HIGH",
                "risk_score": get_risk_score("HIGH"),
                "source_ip": ip,
                "failed_attempts": len(attempts),
                "message": f"Multiple failed login attempts detected from {ip}"
            })

    return alerts


def detect_sql_injection(events):
    alerts = []

    for event in events:
        if event["event_type"] != "waf_blocked":
            continue

        message = event.get("message", "").lower()

        if "sql injection" in message:
            alerts.append({
                "alert_type": "SQL_INJECTION_DETECTED",
                "severity": "HIGH",
                "risk_score": get_risk_score("HIGH"),
                "source_ip": event["source_ip"],
                "rule_id": event["rule_id"],
                "uri": event["uri"],
                "message": event["message"]
            })

    return alerts

def detect_xss(events):
    alerts = []

    for event in events:
        if event["event_type"] != "waf_blocked":
            continue

        message = event.get("message", "").lower()

        if "xss" in message or "cross-site scripting" in message:
            alerts.append({
                "alert_type": "XSS_DETECTED",
                "severity": "HIGH",
                "risk_score": get_risk_score("HIGH"),
                "source_ip": event["source_ip"],
                "rule_id": event["rule_id"],
                "uri": event["uri"],
                "message": event["message"]
            })

    return alerts