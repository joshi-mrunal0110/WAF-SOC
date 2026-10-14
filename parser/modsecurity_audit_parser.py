import re

from parser.event_schema import create_event


def parse_modsecurity_audit_log(log_text):
    """Parse ModSecurity Serial audit-log transactions."""

    events = []
    if not log_text or not log_text.strip():
        return events

    # A transaction begins with a marker such as ---abc123---A--
    # The next line contains the timestamp and connection details.
    transaction_pattern = re.compile(
        r"(?m)^---([A-Za-z0-9]+)---A--\s*\r?\n"
    )
    transaction_matches = list(transaction_pattern.finditer(log_text))

    for index, transaction_match in enumerate(transaction_matches):
        transaction_id = transaction_match.group(1)

        # Include Section A's content, which follows the opening marker.
        start = transaction_match.end()
        end = (
            transaction_matches[index + 1].start()
            if index + 1 < len(transaction_matches)
            else len(log_text)
        )
        transaction = log_text[start:end]

        # Parse each section marker, e.g. ---abc123---B--
        sections = {}
        section_pattern = re.compile(
            rf"(?m)^---{re.escape(transaction_id)}---([A-Z])--\s*\r?$"
        )
        section_matches = list(section_pattern.finditer(transaction))

        # Section A is the content between the opening A marker and
        # the next section marker. The opening marker is outside transaction.
        first_section = re.search(
            rf"(?m)^---{re.escape(transaction_id)}---([A-Z])--\s*\r?$",
            transaction,
        )

        if first_section:
            section_name = first_section.group(1)
            if section_name == "B":
                # Section A content occurs before the first B marker.
                sections["A"] = transaction[:first_section.start()].strip()

        for i, section_match in enumerate(section_matches):
            section_name = section_match.group(1)
            section_start = section_match.end()
            section_end = (
                section_matches[i + 1].start()
                if i + 1 < len(section_matches)
                else len(transaction)
            )
            sections[section_name] = transaction[
                section_start:section_end
            ].strip()

        # Section A: timestamp and connection information.
        section_a = sections.get("A", "")

        timestamp_match = re.search(
            r"\[([^\]]+)\]",
            section_a,
        )
        connection_match = re.search(
            r"\]\s+\S+\s+"
            r"(\d{1,3}(?:\.\d{1,3}){3})\s+\d+\s+"
            r"\S+\s+\d+",
            section_a,
        )

        timestamp = timestamp_match.group(1) if timestamp_match else None
        source_ip = connection_match.group(1) if connection_match else None

        # Section B: HTTP request line.
        section_b = sections.get("B", "")
        request_match = re.search(
            r"(?m)^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)"
            r"\s+(\S+)\s+HTTP/\d(?:\.\d)?$",
            section_b,
        )

        method = request_match.group(1) if request_match else None
        uri = request_match.group(2) if request_match else None

        # Section F: HTTP response status.
        section_f = sections.get("F", "")
        status_match = re.search(
            r"(?m)^HTTP/\d(?:\.\d)?\s+(\d{3})",
            section_f,
        )
        status_code = int(status_match.group(1)) if status_match else None

        # Section H: ModSecurity rule messages.
        section_h = sections.get("H", "")
        rule_pattern = re.compile(
            r'\[id "(\d+)"\].*?\[msg "([^"]*)"\].*?\[severity "([^"]*)"\]'
        )

        severity_map = {
            "0": "CRITICAL",
            "1": "CRITICAL",
            "2": "HIGH",
            "3": "MEDIUM",
            "4": "MEDIUM",
            "5": "LOW",
        }

        for rule_match in rule_pattern.finditer(section_h):
            rule_id, message, severity_value = rule_match.groups()
            severity = severity_map.get(severity_value, "MEDIUM")

            events.append(
                create_event(
                    source="modsecurity",
                    event_type="waf_detection",
                    timestamp=timestamp,
                    source_ip=source_ip,
                    action="detected",
                    method=method,
                    uri=uri,
                    status_code=status_code,
                    rule_id=rule_id,
                    message=message,
                    severity=severity,
                )
            )

    return events
