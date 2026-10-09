# WAF-SOC — System Architecture

## 1. Project Overview

WAF-SOC is a prototype security monitoring and incident response platform. It collects log entries from multiple sources, converts them into a common event format, applies detection rules, and stores generated alerts.

The project is being developed in stages, starting with simulated logs and gradually moving toward real WAF integration, database storage, and a SOC dashboard.

## 2. Current Architecture

```text
          SIMULATED LOG SOURCES
                    |
       +------------+------------+
       |            |            |
   Nginx Logs    Linux Auth    WAF Logs
   access.log    auth.log      waf.log
       |            |            |
       v            v            v
   Nginx Parser  Auth Parser  WAF Parser
       |            |            |
       +------------+------------+
                    |
                    v
          Common Event Schema
                    |
                    v
        Unified Python Collector
                    |
                    v
       normalized_events.json
                    |
                    v
            Detection Engine
           /        |        \
          v         v         v
     Brute Force  SQLi       XSS
       Detector  Detector  Detector
           \        |        /
                    |
                    v
              Security Alerts
                    |
                    v
               alerts.json
```

## 3. Main Components

### Log Sources

The current implementation uses three simulated sources:

- Nginx HTTP access logs.
- Linux SSH authentication logs.
- WAF events representing blocked and allowed requests.

These logs are sample data and do not yet come from live services.

### Parsers

Each parser extracts relevant fields from its source format.

- `parser/nginx_parser.py`
- `parser/auth_parser.py`
- `parser/waf_parser.py`

The parsers use regular expressions and return structured events.

### Common Event Schema

`parser/event_schema.py` provides the shared structure for normalized events.

Fields include timestamp, source, event type, source IP, username, action, HTTP method, URI, status code, WAF rule ID, message, and severity.

This common representation simplifies downstream processing.

### Unified Collector

`collector/log_collector.py` reads the three log files, invokes the corresponding parsers, combines the parsed events, and saves them to `logs/normalized_events.json`.

### Detection Engine

`detection/detection_engine.py` currently contains three rules:

1. **Brute-force detection:** counts failed authentication events by source IP and raises an alert at the configured threshold.
2. **SQL injection detection:** matches SQL injection indicators in blocked WAF event messages.
3. **XSS detection:** matches XSS indicators in blocked WAF event messages.

These are basic prototype rules, not production-grade detection logic.

### Alert Storage

`tests/test_detection.py` runs the current detection functions and saves their results to `logs/alerts.json`.

The alert records include fields such as alert type, severity, source IP, and rule-specific details.

### Risk Scoring

The prototype maps severity categories to numeric scores:

- LOW: 25
- MEDIUM: 50
- HIGH: 75
- CRITICAL: 100

This is a fixed demonstration mapping. It is not a probability that an attack will succeed.

## 4. Current Data Flow

1. Sample log files contain raw entries.
2. The unified collector reads each file.
3. The appropriate parser extracts fields.
4. Each parser creates an event using the common schema.
5. The collector writes normalized events to JSON.
6. The detection engine evaluates the events.
7. Matching rules produce alerts.
8. The alert script writes alerts to JSON.

## 5. Planned Architecture

The target architecture will extend the current prototype:

```text
Real HTTP Traffic
       |
       v
Nginx + ModSecurity + OWASP CRS
       |
       v
Real WAF and Access Logs
       |
       v
Python Collector and Parsers
       |
       v
Detection and Correlation Engine
       |
       +-------------------+
       |                   |
       v                   v
PostgreSQL Database    AI Analyst
       |                   |
       +---------+---------+
                 |
                 v
          FastAPI Backend
                 |
                 v
          React SOC Dashboard
```

The exact integration will be implemented and validated in later development stages.

## 6. Planned Improvements

- Automated unit tests.
- Time-window-based detection.
- Alert deduplication.
- More robust risk scoring.
- PostgreSQL storage.
- FastAPI endpoints.
- React dashboard.
- Real Nginx and ModSecurity log integration.
- Controlled testing against an isolated vulnerable application.
- AI-assisted alert explanation and investigation support.
- MITRE ATT&CK mapping.
- Deployment and documentation improvements.

## 7. Security Considerations

- Use only authorized test systems.
- Keep vulnerable applications isolated.
- Avoid exposing lab services to the public internet.
- Protect secrets using environment variables and appropriate access controls.
- Treat AI-generated explanations as analyst assistance, not definitive evidence.
- Preserve enough event context to investigate alerts.

## 8. Scope and Limitations

The current version demonstrates log parsing, event normalization, basic rule-based detection, and JSON alert generation.

It does not yet provide live traffic inspection, production-grade correlation, a database-backed alert lifecycle, or an operational SOC dashboard.

Those features are planned and must be implemented and tested before the project can be described as a fully integrated WAF-SOC platform.