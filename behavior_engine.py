"""
Behavior Monitoring Engine - Intelligent Cyber Defense Framework
Analyzes user input behavior for anomaly detection.
"""

import re
import urllib.parse


def analyze_keyword_structure(user_input):
    """Analyze the structure of the submitted keyword/input."""
    findings = []

    # Check for excessive length
    if len(user_input) > 50:
        findings.append('long_keyword')

    # Check for special characters
    special_chars = re.findall(r'[^a-zA-Z0-9\s\.\-\_]', user_input)
    if len(special_chars) > 3:
        findings.append('excessive_special_chars')

    # Check for SQL injection patterns
    sql_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|EXEC)\b)",
        r"(--|;|\/\*|\*\/)",
        r"(\bOR\b\s+\b\d+\b\s*=\s*\b\d+\b)",
        r"(\bOR\b\s+['\"].*['\"].*=.*['\"])",
        r"('\s*(OR|AND)\s+')",
        r"(\bUNION\b\s+\bSELECT\b)",
        r"(\b(CHAR|NCHAR|VARCHAR|NVARCHAR)\s*\()",
        r"(0x[0-9a-fA-F]+)",
        r"(\bWAITFOR\b\s+\bDELAY\b)",
        r"(\bBENCHMARK\b\s*\()",
    ]
    for pattern in sql_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            findings.append('sql_injection')
            break

    # Check for XSS patterns
    xss_patterns = [
        r'<\s*script',
        r'javascript\s*:',
        r'on\w+\s*=',
        r'<\s*iframe',
        r'<\s*img[^>]+onerror',
    ]
    for pattern in xss_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            findings.append('xss_attempt')
            break

    # Check for path traversal
    if re.search(r'(\.\./|\.\.\\|%2e%2e)', user_input, re.IGNORECASE):
        findings.append('path_traversal')

    # Check for command injection
    # Detect either: (1) dangerous operators (;, &&, ||, |, backtick, $), OR (2) shell commands
    has_operator = re.search(r'(;|&&|\|\||`|\$)', user_input)
    has_shell_cmd = re.search(r'\b(cat|ls|dir|whoami|pwd|id|uname)\b', user_input, re.IGNORECASE)
    if has_operator or has_shell_cmd:
        findings.append('command_injection')

    # Check for path injection (system file paths)
    path_patterns = [
        r'(/etc/|/proc/|/root/|/home/|/var/www|/usr/bin|/usr/local)',
        r'(C:\\Windows|C:\\Program Files|C:\\Users|C:\\System)',
        r'(/etc/passwd|/etc/shadow|/proc/self)',
    ]
    for pattern in path_patterns:
        if re.search(pattern, user_input, re.IGNORECASE):
            findings.append('path_injection')
            break

    # Check for excessive special character sequences (5+ same char in a row)
    if re.search(r'([^\w\s])\1{4,}', user_input):
        findings.append('excessive_special_chars')

    # Check for URL encoded attacks (e.g., %3Cscript%3E, %27%20OR%201%3D1)
    if '%' in user_input:
        try:
            decoded = urllib.parse.unquote(user_input)
            # If decoded version is different and contains attack patterns
            if decoded != user_input:
                decoded_findings = analyze_keyword_structure(decoded)
                if decoded_findings and 'encoded_attack' not in findings:
                    findings.append('encoded_attack')
        except:
            pass

    return findings


def detect_repeated_requests(request_count, limit):
    """Check if request frequency exceeds the threshold."""
    return request_count >= limit


def build_behavior_report(user_input, findings, repeat_detected):
    """Build a detailed behavior analysis report."""
    details = []

    if 'long_keyword' in findings:
        details.append(f'Input length ({len(user_input)} chars) exceeds safe threshold')
    if 'excessive_special_chars' in findings:
        details.append('Excessive special characters detected')
    if 'sql_injection' in findings:
        details.append('SQL injection pattern detected')
    if 'xss_attempt' in findings:
        details.append('XSS attempt pattern detected')
    if 'path_traversal' in findings:
        details.append('Path traversal attempt detected')
    if 'path_injection' in findings:
        details.append('System path injection attempt detected')
    if 'command_injection' in findings:
        details.append('Command injection pattern detected')
    if 'encoded_attack' in findings:
        details.append('URL encoded attack pattern detected')
    if repeat_detected:
        details.append('Repeated requests from same IP within short window')

    return '; '.join(details) if details else 'No anomalies detected'
