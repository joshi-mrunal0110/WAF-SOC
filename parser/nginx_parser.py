import re

from parser.event_schema import create_event


LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ '
    r'\[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<uri>\S+) (?P<protocol>[^"]+)" '
    r'(?P<status>\d+) (?P<size>\d+)'
)


def parse_nginx_log(line):

    match = LOG_PATTERN.match(line)

    if not match:
        return None

    data = match.groupdict()
    status_code = int(data["status"])

    if status_code >= 500:
        severity = "HIGH"
    elif status_code in [401, 403]:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return create_event(
    source="nginx",
    event_type="http_request",
    timestamp=data["timestamp"],
    source_ip=data["ip"],
    action="request",
    method=data["method"],
    uri=data["uri"],
    status_code=status_code,
    severity=severity
)