# WAF-SOC — Interview Questions and Answers

This document contains interview questions related to the project's implementation and underlying cybersecurity concepts.

---

## Section 1: Project Overview

### Q1. What is WAF-SOC?

WAF-SOC is a security monitoring and incident response project designed to collect web server, authentication, and WAF logs, normalize events, detect suspicious activity, and generate security alerts.

The current version is a Python prototype using simulated logs and JSON files.

### Q2. Why did you build this project?

I wanted to gain practical experience in security monitoring, web attack detection, log analysis, and incident response. The project also helps me understand how WAF and SOC workflows can work together.

### Q3. What technologies are you using?

The current prototype uses Python, regular expressions, JSON, and Python modules. The planned stack includes PostgreSQL, FastAPI, React, Nginx, ModSecurity, and OWASP Core Rule Set (CRS).

### Q4. What is a SOC?

A Security Operations Center monitors systems and networks for security threats, investigates alerts, and coordinates incident response.

### Q5. What is a SIEM?

A Security Information and Event Management (SIEM) system collects and correlates logs from multiple sources to help identify suspicious activity and support security investigations.

Our project implements some foundational SIEM-style functions but is not a complete enterprise SIEM.

---

## Section 2: Log Collection and Parsing

### Q6. What is log parsing?

Log parsing means extracting structured information from raw log entries.

For example, a web server log can be parsed to extract the source IP, HTTP method, requested URI, timestamp, and response status.

### Q7. Why did you create separate parsers?

Different log sources use different formats. Separate parsers keep the code modular, easier to test, and easier to extend.

### Q8. Why did you create a common event schema?

The common schema standardizes events from different sources. This makes it easier to store, filter, analyze, and correlate events in one pipeline.

### Q9. What is the purpose of regular expressions?

Regular expressions match text patterns. We use them to identify fields in structured log entries.

### Q10. Why use JSON?

JSON provides a simple, readable format for storing and exchanging structured events between components.

### Q11. Why do you use `None` for missing fields?

Some fields do not apply to every event. For example, a Linux authentication event has no HTTP method. Using `None` keeps the schema consistent without inventing values.

### Q12. What is the difference between raw and normalized logs?

Raw logs are the original entries produced by a system. Normalized events are parsed and converted into a common structure for analysis.

---

## Section 3: WAF and Web Attacks

### Q13. What is a Web Application Firewall?

A Web Application Firewall monitors HTTP and HTTPS traffic and can detect or block suspicious requests targeting web applications.

### Q14. What is ModSecurity?

ModSecurity is an open-source web application firewall engine that can inspect HTTP traffic and apply security rules.

### Q15. What is OWASP CRS?

OWASP Core Rule Set is a collection of generic detection rules designed to help identify common web attacks, including SQL injection and cross-site scripting.

### Q16. What is SQL injection?

SQL injection occurs when an attacker manipulates application input to interfere with database queries.

Defenses include parameterized queries, input validation, least-privilege database accounts, and appropriate security monitoring.

### Q17. What is cross-site scripting (XSS)?

XSS occurs when an application allows untrusted content to execute as script in another user's browser.

Defenses include context-aware output encoding, safe templating, and appropriate Content Security Policy configuration.

### Q18. Does the current project inspect raw HTTP traffic?

Not yet. The current prototype parses simulated WAF log entries. Real HTTP traffic inspection through Nginx and ModSecurity is planned for a later stage.

---

## Section 4: Detection Engineering

### Q19. How does brute-force detection work?

The current detector groups authentication failure events by source IP. If an IP reaches the configured failure threshold, the detector generates a `BRUTE_FORCE_SUSPECTED` alert.

The current implementation counts failures across the loaded dataset. A time-based window is a planned improvement.

### Q20. How does SQL injection detection work in your prototype?

The detector examines WAF events classified as blocked and searches the event message for the phrase "SQL injection". Matching events produce SQL injection alerts.

### Q21. How does XSS detection work?

The detector examines blocked WAF events for message indicators such as "XSS" or "cross-site scripting". Matching events produce XSS alerts.

### Q22. Are these detectors sufficient for production?

No. They are initial rule-based detectors. Production monitoring would require more reliable event sources, time-aware correlation, contextual analysis, testing against false positives, and additional security controls.

### Q23. What is a false positive?

A false positive occurs when legitimate activity is incorrectly identified as malicious.

### Q24. What is a false negative?

A false negative occurs when malicious activity is not detected.

### Q25. How could you improve brute-force detection?

Use a rolling time window, group failures by account and source IP, add successful-login context, configure thresholds, and consider distributed attempts from multiple IPs.

### Q26. Why can source IP alone be insufficient?

Attackers may use proxies, VPNs, shared networks, or botnets. Multiple users may also share one public IP. IP addresses should be combined with other context.

---

## Section 5: Severity, Risk and Alerts

### Q27. What is the difference between severity and risk score?

Severity is a categorical label such as LOW, MEDIUM, HIGH, or CRITICAL. A risk score is a numeric value used to help prioritize alerts.

### Q28. How is risk score calculated in the current project?

The prototype maps LOW to 25, MEDIUM to 50, HIGH to 75, and CRITICAL to 100. This is a fixed mapping, not a validated probability of compromise.

### Q29. Why save alerts to a separate file?

Separating alerts from raw or normalized events makes it easier to inspect detection results and later connect the alert stream to a dashboard or database.

### Q30. What is alert deduplication?

Alert deduplication identifies repeated alerts representing the same underlying activity and reduces unnecessary duplication.

### Q31. What would you include in an incident record?

An incident record could include an identifier, alert type, severity, risk score, source IP, timestamps, evidence, investigation notes, status, and response actions.

---

## Section 6: Architecture and Future Improvements

### Q32. Why use Python?

Python provides convenient tools for text processing, regular expressions, JSON handling, testing, API development, and security automation.

### Q33. How would you process millions of events?

Use streaming ingestion, efficient parsers, message queues, indexed storage, batching, monitoring, and horizontal scaling where necessary.

### Q34. Why add PostgreSQL?

PostgreSQL would provide persistent structured storage, indexing, filtering, and querying for events and alerts.

### Q35. Why use FastAPI?

FastAPI can expose Python functionality through HTTP APIs so that a frontend can retrieve alerts, event statistics, and incident details.

### Q36. Why use React?

React can provide an interactive SOC dashboard with alert tables, severity indicators, charts, and investigation views.

### Q37. How would you integrate real WAF logs?

Configure an isolated test environment with Nginx, ModSecurity, and OWASP CRS. Generate controlled test traffic, inspect the resulting logs, and adapt the collector to process the real log format.

### Q38. How would you secure the platform?

Use authentication and authorization, input validation, secret management, restricted network access, secure database permissions, audit logging, and controlled testing environments.

---

## Interview Preparation Rule

Be honest about the implementation. Distinguish between features that are implemented, features that have been tested, and features that are only planned. Be prepared to explain the code and its limitations rather than only memorizing definitions.