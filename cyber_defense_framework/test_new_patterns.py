#!/usr/bin/env python3
"""Test new attack pattern detections"""

from behavior_engine import analyze_keyword_structure
from risk_scoring import calculate_risk_score

tests = [
    ('&&', 'Command injection - operators'),
    ('/etc/passwd', 'Path injection'),
    ('C:\\Windows\\System32', 'Windows path injection'),
    ('%3Cscript%3E', 'URL encoded XSS'),
    ('%27%20OR%201%3D1', 'URL encoded SQL injection'),
    ('$$$$$$$$', 'Special char spam (5+)'),
    ('weather', 'Normal - should pass'),
]

print('=== PATTERN DETECTION TEST ===\n')
for test_input, desc in tests:
    findings = analyze_keyword_structure(test_input)
    result = calculate_risk_score(test_input, '127.0.0.1')
    status = 'ABNORMAL' if result['status'] == 'abnormal' else 'NORMAL'
    print(f'{desc}')
    print(f'  Input: {test_input}')
    print(f'  Findings: {findings}')
    score = result['risk_score']
    thresh = result['threshold']
    print(f'  Risk Score: {score}/{thresh} ({status})')
    print()
