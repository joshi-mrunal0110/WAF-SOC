# WAF-SOC — Daily Progress Log

**Project:** WAF Security Monitoring & Incident Response Platform  
**Development started:** October 2026  
**Current phase:** Log Collection and Detection Foundation  
**Status:** In progress

---

## Day 1 — Log Collection and Detection Foundation

**Date:** 7 October 2026

### Objectives

- Set up the project structure and Python environment.
- Process logs from multiple sources.
- Normalize events into a common format.
- Implement initial security detection rules.
- Generate and store security alerts.

### Work Completed

#### 1. Project Setup
- Created the `waf-soc` project directory.
- Created directories for the collector, parser, detection engine, tests, and logs.
- Created a Python virtual environment.
- Created the initial README file.
- Added `__init__.py` files to the Python package directories.

#### 2. Log Collection
Created simulated log files for three sources:

- Nginx HTTP access logs.
- Linux SSH authentication logs.
- Web Application Firewall (WAF) logs.

Implemented a Python collector to read logs from all three sources and pass each entry to its corresponding parser.

#### 3. Log Parsing
Created separate parsers:

- `nginx_parser.py`
- `auth_parser.py`
- `waf_parser.py`

Each parser extracts relevant information from its log format.

#### 4. Event Normalization
Created `event_schema.py` to convert parsed entries into a common structure.

The common event fields include:

- Timestamp
- Source
- Event type
- Source IP
- Username
- Action
- HTTP method
- URI
- HTTP status code
- WAF rule ID
- Message
- Severity

Missing fields are represented using `None`, which becomes `null` when serialized to JSON.

#### 5. Severity Classification
Implemented initial severity classifications:

- Normal HTTP requests: LOW
- HTTP 401 and 403 responses: MEDIUM
- HTTP 500 and above: HIGH
- Failed authentication: MEDIUM
- Successful authentication: LOW
- Blocked WAF events: HIGH
- Allowed WAF events: LOW

These are initial prototype rules and can be refined later.

#### 6. Detection Engine
Created `detection/detection_engine.py`.

Implemented three detection functions:

- `detect_brute_force()`
- `detect_sql_injection()`
- `detect_xss()`

The brute-force detector counts authentication failures by source IP and raises an alert when the configured threshold is reached.

The SQL injection and XSS detectors inspect parsed WAF events for matching message indicators.

#### 7. Alert Generation and Risk Scoring
- Generated security alerts from normalized events.
- Saved alerts to `logs/alerts.json`.
- Added a numeric risk score based on severity.

Initial risk-score mapping:

| Severity | Risk score |
|---|---:|
| LOW | 25 |
| MEDIUM | 50 |
| HIGH | 75 |
| CRITICAL | 100 |

#### 8. Event Summary
Added summary output for:

- Total collected events
- Nginx events
- Authentication events
- WAF events
- Blocked WAF events
- Allowed WAF events
- Alert counts by severity

### Issues Encountered and Solutions

**Issue 1: Python import errors**

- Cause: Python modules were run from a subdirectory rather than the project root.
- Solution: Changed to the project root and used module execution, such as `python -m tests.test_parser`.

**Issue 2: Different log formats**

- Cause: Nginx, Linux authentication, and WAF logs have different structures.
- Solution: Implemented separate parsers that produce a shared event schema.

**Issue 3: Alerts were initially printed only in the terminal**

- Cause: Detection results were not being persisted.
- Solution: Saved the combined alert list to `logs/alerts.json`.

### Concepts Practiced

- Python modules and packages
- Regular expressions
- File handling
- JSON serialization
- Log parsing and normalization
- Rule-based security detection
- Event severity and risk scoring
- Basic SIEM architecture

### Testing Performed

- Ran the Nginx parser test.
- Ran the authentication parser test.
- Ran the WAF parser test.
- Ran the unified log collector.
- Ran the brute-force, SQL injection, and XSS detection functions.

The simulated pipeline produced 17 normalized events from the initial datasets and 4 alerts from the three initial detection rules.

### Known Limitations

- Logs are simulated rather than collected from a real WAF.
- Events are stored in JSON files rather than PostgreSQL.
- Brute-force detection counts failures in the loaded dataset without a time-window constraint.
- SQL injection and XSS detection rely on WAF event messages.
- Alert deduplication and incident lifecycle management are not implemented yet.
- Automated unit tests are planned.

### Next Steps

1. Add automated unit tests for detection rules.
2. Improve detection accuracy and reduce false positives.
3. Add time-window-based brute-force detection.
4. Add alert deduplication and improved risk scoring.
5. Integrate PostgreSQL for persistent storage.

---

## Development Notes

Only record issues that actually occurred. Add new entries after each development session, including what was completed, what failed, how it was resolved, and what you learned.

## Day 2 — Detection Engine Testing — Follow-up Session

**Date:** 9 October 2026

### Completed
- Added automated unit tests using Python's `unittest` framework.
- Tested brute-force detection at and below its threshold.
- Verified that unrelated events do not trigger brute-force alerts.
- Tested SQL injection and XSS detection.
- Added negative tests for unrelated events.
- Verified severity and risk-score fields for all three alert types.
- Ran test discovery across the `tests` directory.

### Issues Encountered
- No new issues reported during this session.

### Concepts Practiced
- Unit testing
- Positive and negative testing
- Threshold boundary testing
- Assertions
- False-positive prevention
- Test discovery

### Next Steps
- Improve parser tests so they use actual assertions rather than only printing output.
- Review detection logic for edge cases.
- Prepare the detection engine for database integration.


## Testing Milestone — 9 October 2026

### Work completed
- Converted the Nginx parser test into an automated unit test.
- Added authentication parser tests for failed login, successful login, and invalid input.
- Added WAF parser tests for blocked requests, allowed requests, and invalid input.
- Ran the complete test suite using:
  `python -m unittest discover -s tests -v`

### Verification results
- 14 tests executed successfully.
- Test suite completed with `OK`.
- No test failures or errors were reported.
- The simulated detection run generated four alerts:
  - 1 suspected brute-force attack
  - 2 SQL injection detections
  - 1 XSS detection

### Concepts learned
- Unit testing validates individual components.
- Negative tests verify that unrelated or invalid inputs do not trigger detections.
- Test discovery allows multiple test modules to be executed together.
- Simulated log detections demonstrate the prototype's behavior, not real-world attack prevention.

### Issues encountered
- No test failures were reported in this run.

### WAF-SOC Lab — Real WAF Integration

**Date:** 13 October 2026

**Work completed**
- Configured a Kali Linux VM with VMware Host-only networking and a separate NAT adapter.
- Installed Nginx, the ModSecurity v3 Nginx connector, and OWASP Core Rule Set (CRS).
- Configured ModSecurity in `DetectionOnly` mode.
- Configured the CRS include file and enabled ModSecurity for the default Nginx virtual host.
- Verified that the ModSecurity audit log exists at `/var/log/nginx/modsec_audit.log`.
- Sent a SQL injection test request to the local Nginx server.

**Verified detection evidence**
- Test URL: `http://127.0.0.1/?id=1%20OR%201=1`
- HTTP response: `200 OK`
- CRS rule ID: `942100`
- Detection: SQL injection pattern identified by libinjection.
- Anomaly evaluation rule: `949110`
- Anomaly score reported: `8`
- Audit log: `/var/log/nginx/modsec_audit.log`

**Result**

The OWASP CRS detected the SQL injection test pattern and recorded the detection in the ModSecurity audit log. The request returned HTTP 200 while ModSecurity was configured in `DetectionOnly` mode. This confirms detection and logging for this test case; it does not yet verify blocking mode or integration with the Python collector.

**Concepts learned**
- Difference between detection-only and blocking modes.
- How OWASP CRS rules identify suspicious HTTP requests.
- How ModSecurity audit logs provide evidence for security investigations.
- Why HTTP response status and WAF detection results must be evaluated separately.

### Real ModSecurity Parser Integration

**Date:** 14 October 2026

**Work completed**
- Created a Python parser for ModSecurity serial audit logs.
- Parsed real audit-log transaction sections A, B, F, H, and Z.
- Extracted timestamps, source IP addresses, HTTP methods, request URIs, response status codes, rule IDs, detection messages, and severity levels.
- Successfully parsed three security events from the saved ModSecurity sample log.
- Removed temporary debugging statements after verifying the parser.
- Ran the complete unit test suite successfully: 18 tests passed.

**Verified detection evidence**
- Rule `920350`: Numeric IP address in the Host header.
- Rule `942100`: SQL injection detected via libinjection.
- Rule `949110`: Inbound anomaly score exceeded, with a total anomaly score of 8.
- Source IP: `127.0.0.1`
- HTTP response status: `200`

**Result**

The WAF-SOC project can now parse the saved real ModSecurity audit-log sample and convert its rule messages into normalized security events. All 18 unit tests pass.

**Current limitation**

The parser has been tested against a saved audit-log sample. Continuous collection of new audit-log entries from the Kali VM into the Python application has not yet been implemented.

**Concepts learned**
- Structure of ModSecurity serial audit logs.
- How OWASP CRS rule IDs and severity values appear in audit messages.
- Difference between a WAF detection and an HTTP response status.
- Importance of validating real-world input in addition to unit tests.