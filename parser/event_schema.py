from datetime import datetime


def create_event(
    source,
    event_type,
    timestamp,
    source_ip=None,
    username=None,
    action=None,
    method=None,
    uri=None,
    status_code=None,
    rule_id=None,
    message=None,
    severity="LOW"
):

    return {
        "timestamp": timestamp,
        "source": source,
        "event_type": event_type,
        "source_ip": source_ip,
        "username": username,
        "action": action,
        "method": method,
        "uri": uri,
        "status_code": status_code,
        "rule_id": rule_id,
        "message": message,
        "severity": severity
    }