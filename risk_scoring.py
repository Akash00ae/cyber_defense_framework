"""
Dynamic Risk Scoring Engine - Intelligent Cyber Defense Framework
Calculates risk scores and classifies users based on configurable parameters.
"""

from behavior_engine import analyze_keyword_structure, detect_repeated_requests, build_behavior_report
from database import get_risk_config, get_recent_requests_by_ip


def calculate_risk_score(user_input, ip_address):
    """
    Calculate the risk score for a given user input.
    Returns a dict with score, status, details, and breakdown.
    """
    config = get_risk_config()

    # Extract config values
    long_kw_score = config.get('long_keyword_score', 2)
    special_chars_score = config.get('special_chars_score', 3)
    repeated_score = config.get('repeated_requests_score', 4)
    sqli_score = config.get('sql_injection_score', 5)
    threshold = config.get('risk_threshold', 5)
    repeat_window = config.get('repeat_window_seconds', 60)
    repeat_limit = config.get('repeat_count_limit', 3)

    # Run behavior analysis
    findings = analyze_keyword_structure(user_input)

    # Check for repeated requests
    recent_count = get_recent_requests_by_ip(ip_address, repeat_window)
    repeat_detected = detect_repeated_requests(recent_count, repeat_limit)

    # Calculate score
    score = 0
    breakdown = []

    if 'long_keyword' in findings:
        score += long_kw_score
        breakdown.append(f'Long keyword: +{long_kw_score}')

    if 'excessive_special_chars' in findings:
        score += special_chars_score
        breakdown.append(f'Special characters: +{special_chars_score}')

    if 'sql_injection' in findings:
        score += sqli_score
        breakdown.append(f'SQL injection pattern: +{sqli_score}')

    if 'xss_attempt' in findings:
        score += special_chars_score
        breakdown.append(f'XSS attempt: +{special_chars_score}')

    if 'path_traversal' in findings:
        score += special_chars_score
        breakdown.append(f'Path traversal: +{special_chars_score}')

    if 'command_injection' in findings:
        score += sqli_score
        breakdown.append(f'Command injection: +{sqli_score}')

    if 'path_injection' in findings:
        score += sqli_score
        breakdown.append(f'System path injection: +{sqli_score}')

    if 'encoded_attack' in findings:
        score += sqli_score
        breakdown.append(f'Encoded attack pattern: +{sqli_score}')

    if repeat_detected:
        score += repeated_score
        breakdown.append(f'Repeated requests ({recent_count}x): +{repeated_score}')

    # Classify
    status = 'abnormal' if score >= threshold else 'normal'

    # Build detailed report
    details = build_behavior_report(user_input, findings, repeat_detected)

    return {
        'risk_score': score,
        'status': status,
        'threshold': threshold,
        'details': details,
        'breakdown': breakdown,
        'findings': findings,
        'repeated': repeat_detected
    }
