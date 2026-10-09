import json

from parser.nginx_parser import parse_nginx_log
from parser.auth_parser import parse_auth_log
from parser.waf_parser import parse_waf_log


ACCESS_LOG = "logs/access.log"
AUTH_LOG = "logs/auth.log"
WAF_LOG = "logs/waf.log"

OUTPUT_FILE = "logs/normalized_events.json"


def collect_logs(log_file, parser):
    events = []

    with open(log_file, "r") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            event = parser(line)

            if event:
                events.append(event)

    return events


def save_events(events):
    with open(OUTPUT_FILE, "w") as file:
        json.dump(events, file, indent=4)


if __name__ == "__main__":
    nginx_events = collect_logs(
        ACCESS_LOG,
        parse_nginx_log
    )

    auth_events = collect_logs(
        AUTH_LOG,
        parse_auth_log
    )

    waf_events = collect_logs(
        WAF_LOG,
        parse_waf_log
    )

    all_events = nginx_events + auth_events + waf_events

    save_events(all_events)

    waf_blocked = sum(
        1 for event in waf_events
        if event["event_type"] == "waf_blocked"
    )

    waf_allowed = sum(
        1 for event in waf_events
        if event["event_type"] == "waf_allowed"
    )

    print("\n===== WAF-SOC EVENT SUMMARY =====")
    print(f"Total events: {len(all_events)}")
    print(f"Nginx events: {len(nginx_events)}")
    print(f"Authentication events: {len(auth_events)}")
    print(f"WAF events: {len(waf_events)}")
    print(f"WAF blocked events: {waf_blocked}")
    print(f"WAF allowed events: {waf_allowed}")
    print("=================================")

    print(f"\nSaved normalized events to: {OUTPUT_FILE}")