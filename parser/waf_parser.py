import re

from parser.event_schema import create_event


WAF_LOG_PATTERN = re.compile(
    r'(?P<timestamp>\S+ \S+) '
    r'(?P<ip>\S+) '
    r'"(?P<request>[^"]+)" '
    r'"(?P<message>[^"]+)" '
    r'"(?P<rule_id>[^"]+)"'
)


def parse_waf_log(line):
    match = WAF_LOG_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()

    request_parts = data["request"].split(" ", 1)

    method = request_parts[0]
    uri = request_parts[1] if len(request_parts) > 1 else None

    if data["rule_id"] == "-":
        event_type = "waf_allowed"
        rule_id = None
    else:
        event_type = "waf_blocked"
        rule_id = data["rule_id"]

    if rule_id:
        severity = "HIGH"
    else:
        severity = "LOW"

    return create_event(
        source="waf",
        event_type=event_type,
        timestamp=data["timestamp"],
        source_ip=data["ip"],
        action="blocked" if rule_id else "allowed",
        method=method,
        uri=uri,
        rule_id=rule_id,
        message=data["message"],
        severity=severity
    )