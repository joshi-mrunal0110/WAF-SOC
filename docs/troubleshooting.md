# WAF-SOC — Troubleshooting Log

This document records the actual issues encountered during WAF-SOC development and the solutions used to resolve them.

## Issue 1: Python Module Import Error

**Problem:**  
Python imports failed when running a test module from inside a project subdirectory.

**Cause:**  
The terminal was running from the `collector` directory instead of the project root. Python could not resolve imports such as `parser.nginx_parser` correctly.

**Solution:**
1. Navigated to the project root:
   `cd D:\waf-soc`
2. Ran the test as a module:
   `python -m tests.test_parser`

**Result:**  
The parser test executed successfully, and the import issue was resolved.

**Key learning:**  
Running Python modules from the project root with `python -m package.module` helps Python resolve project package imports correctly.

---

## Issue 2: Handling Different Log Formats

**Problem:**  
Nginx access logs, Linux authentication logs, and WAF logs have different formats and contain different fields.

**Cause:**  
Each log source records information differently. A single parsing pattern could not correctly extract the required fields from every source.

**Solution:**
- Created a separate parser for each log source:
  - `parser/nginx_parser.py`
  - `parser/auth_parser.py`
  - `parser/waf_parser.py`
- Created `parser/event_schema.py` to standardize the parsed events.
- Updated the parsers to use the common event schema.

**Result:**  
The three parsers could produce events in a shared structure, allowing the collector to combine them into `logs/normalized_events.json`.

**Key learning:**  
Separate parsers and a common event schema make a multi-source log processing pipeline easier to maintain and extend.