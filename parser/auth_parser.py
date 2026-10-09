import re

from parser.event_schema import create_event


AUTH_LOG_PATTERN = re.compile(
    r'(?P<month>\w+)\s+'
    r'(?P<day>\d+)\s+'
    r'(?P<time>\S+)\s+'
    r'(?P<hostname>\S+)\s+'
    r'sshd\[(?P<pid>\d+)\]:\s+'
    r'(?P<action>Accepted|Failed)\s+password\s+for\s+'
    r'(?P<username>\S+)\s+from\s+'
    r'(?P<ip>\S+)\s+port\s+'
    r'(?P<port>\d+)'
)


def parse_auth_log(line):

    match = AUTH_LOG_PATTERN.search(line)

    if not match:
        return None

    data = match.groupdict()

    if data["action"] == "Failed":
        event_type = "authentication_failure"
        severity = "MEDIUM"
    else:
        event_type = "authentication_success"
        severity = "LOW"

    return create_event(
        source="linux_auth",
        event_type=event_type,
        timestamp=f'{data["month"]} {data["day"]} {data["time"]}',
        source_ip=data["ip"],
        username=data["username"],
        action=data["action"].lower(),
        severity=severity
    )