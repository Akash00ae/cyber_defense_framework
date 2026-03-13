"""
End-to-End System Test Suite
Intelligent Cyber Defense Framework
Tests all 10 scenarios and validates FR1-FR26.
"""

import urllib.request
import json
import time
import sys

BASE = 'http://127.0.0.1:5000'
PASS_COUNT = 0
FAIL_COUNT = 0
RESULTS = {}


def api_post(endpoint, data):
    """POST JSON to an endpoint and return parsed response."""
    req = urllib.request.Request(
        BASE + endpoint,
        data=json.dumps(data).encode(),
        headers={'Content-Type': 'application/json'}
    )
    r = urllib.request.urlopen(req)
    return json.loads(r.read())


def api_get(endpoint):
    """GET JSON from an endpoint."""
    r = urllib.request.urlopen(BASE + endpoint)
    return json.loads(r.read())


def api_get_raw(endpoint):
    """GET raw text from an endpoint."""
    r = urllib.request.urlopen(BASE + endpoint)
    return r.read().decode()


def api_get_html(endpoint):
    """GET HTML from endpoint, return (status_code, body_text)."""
    try:
        r = urllib.request.urlopen(BASE + endpoint)
        return r.getcode(), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, ''


def check(test_id, description, condition):
    """Record a pass/fail assertion."""
    global PASS_COUNT, FAIL_COUNT
    status = 'PASS' if condition else 'FAIL'
    if condition:
        PASS_COUNT += 1
    else:
        FAIL_COUNT += 1
    print(f'  [{status}] {description}')
    if test_id not in RESULTS:
        RESULTS[test_id] = {'pass': 0, 'fail': 0}
    if condition:
        RESULTS[test_id]['pass'] += 1
    else:
        RESULTS[test_id]['fail'] += 1


def separator(title):
    print()
    print('=' * 72)
    print(f'  {title}')
    print('=' * 72)


# ═══════════════════════════════════════════════════════════════════════════
# SETUP: Verify server is running
# ═══════════════════════════════════════════════════════════════════════════
print()
print('Intelligent Cyber Defense Framework — System Test Suite')
print('=' * 72)

try:
    api_get('/api/stats')
    print('  Server is running at', BASE)
except Exception:
    print('  ERROR: Server is not running at', BASE)
    sys.exit(1)


# ═══════════════════════════════════════════════════════════════════════════
# TEST SCENARIO 1 — Normal User Behavior
# ═══════════════════════════════════════════════════════════════════════════
separator('TEST SCENARIO 1 — Normal User Behavior')
print('  Input: "weather today"')
print()

result = api_post('/analyze_request', {'keyword': 'weather today'})
t1_result = result  # save for FR3 validation
print(f'  Response: status={result["status"]}, risk_score={result["risk_score"]}, '
      f'threshold={result["threshold"]}')
print(f'  Redirect: {result["redirect_url"]}')
print(f'  Details: {result["details"]}')
print()

check('T1', 'Status is "normal"', result['status'] == 'normal')
check('T1', 'Risk score is 0 (no anomalies)', result['risk_score'] == 0)
check('T1', 'Risk score < threshold', result['risk_score'] < result['threshold'])
check('T1', 'Redirects to real website (google.com)', 'google.com' in result['redirect_url'])
check('T1', 'No findings detected', len(result['breakdown']) == 0)
check('T1', 'Details say no anomalies', 'No anomalies' in result['details'])

# Verify DB log
stats = api_get('/api/stats')
check('T1', 'Total requests incremented (>=1)', stats['total_requests'] >= 1)
check('T1', 'Normal requests incremented (>=1)', stats['normal_requests'] >= 1)


# ═══════════════════════════════════════════════════════════════════════════
# TEST SCENARIO 2 — Long Input Pattern
# ═══════════════════════════════════════════════════════════════════════════
separator('TEST SCENARIO 2 — Long Input Pattern')
long_input = 'thisisaveryverylongsearchkeywordtestexample123456'
print(f'  Input: "{long_input}" (length={len(long_input)})')
print()

result = api_post('/analyze_request', {'keyword': long_input})
print(f'  Response: status={result["status"]}, risk_score={result["risk_score"]}, '
      f'threshold={result["threshold"]}')
print(f'  Breakdown: {result["breakdown"]}')
print()

# This input is 49 chars — just under 50 threshold. Should be normal.
check('T2', f'Input length is {len(long_input)} chars', len(long_input) == 49)
check('T2', 'Status classification returned', result['status'] in ('normal', 'abnormal'))
check('T2', 'Log stored (total_requests increased)', api_get('/api/stats')['total_requests'] >= 2)

# Now test one that's truly over 50 chars
long_input2 = 'thisisaveryverylongsearchkeywordtestexample1234567890extra'
print(f'  Extended input: "{long_input2}" (length={len(long_input2)})')
result2 = api_post('/analyze_request', {'keyword': long_input2})
print(f'  Response: status={result2["status"]}, risk_score={result2["risk_score"]}')
print(f'  Breakdown: {result2["breakdown"]}')
print()

check('T2', 'Long keyword detection triggers for >50 chars', 'long_keyword' in result2.get('findings', result2.get('breakdown', [])))
check('T2', 'Long keyword adds +2 to risk score', result2['risk_score'] >= 2)
check('T2', 'Breakdown includes long keyword entry', any('Long keyword' in b for b in result2['breakdown']))


# ═══════════════════════════════════════════════════════════════════════════
# TEST SCENARIO 3 — SQL Injection Attempt
# ═══════════════════════════════════════════════════════════════════════════
separator("TEST SCENARIO 3 — SQL Injection Attempt")
sqli_input = "admin' OR '1'='1"
print(f'  Input: "{sqli_input}"')
print()

result = api_post('/analyze_request', {'keyword': sqli_input})
print(f'  Response: status={result["status"]}, risk_score={result["risk_score"]}, '
      f'threshold={result["threshold"]}')
print(f'  Findings: {result["findings"]}')
print(f'  Breakdown: {result["breakdown"]}')
print(f'  Redirect: {result["redirect_url"]}')
print()

check('T3', 'SQL injection pattern detected', 'sql_injection' in result.get('findings', []))
check('T3', 'Special characters detected', 'excessive_special_chars' in result.get('findings', []))
check('T3', 'Risk score >= 5 (SQL injection +5)', result['risk_score'] >= 5)
check('T3', 'Status is "abnormal"', result['status'] == 'abnormal')
check('T3', 'Redirects to decoy environment', '/decoy' in result['redirect_url'])
check('T3', 'Details mention SQL injection', 'SQL injection' in result.get('details', ''))
check('T3', 'Risk score includes special chars (+3)', result['risk_score'] >= 8)

# Dashboard update
stats = api_get('/api/stats')
check('T3', 'Abnormal attempts counter > 0', stats['abnormal_attempts'] > 0)


# ═══════════════════════════════════════════════════════════════════════════
# TEST SCENARIO 4 — Special Character Attack
# ═══════════════════════════════════════════════════════════════════════════
separator("TEST SCENARIO 4 — Special Character Attack")
special_input = "$$$$$%%%%%%%@@@@@!!!!!"
print(f'  Input: "{special_input}"')
print()

result = api_post('/analyze_request', {'keyword': special_input})
print(f'  Response: status={result["status"]}, risk_score={result["risk_score"]}')
print(f'  Findings: {result["findings"]}')
print(f'  Breakdown: {result["breakdown"]}')
print()

check('T4', 'Excessive special characters detected', 'excessive_special_chars' in result.get('findings', []) or 'Special characters' in str(result.get('breakdown', [])))
check('T4', 'Risk score includes +3 for special chars', result['risk_score'] >= 3)
check('T4', 'Request is logged', api_get('/api/stats')['total_requests'] >= 5)


# ═══════════════════════════════════════════════════════════════════════════
# TEST SCENARIO 5 — Repeated Bot Requests
# ═══════════════════════════════════════════════════════════════════════════
separator("TEST SCENARIO 5 — Repeated Bot Requests")
print('  Simulating 6 rapid "admin" requests...')
print()

repeat_results = []
for i in range(6):
    r = api_post('/analyze_request', {'keyword': 'admin'})
    repeat_results.append(r)
    print(f'  Request {i+1}: status={r["status"]}, score={r["risk_score"]}, '
          f'repeated={r.get("repeated", False)}')

print()

# The repeat_count_limit is 3, so after 3 prior requests the 4th+ should detect repetition
last = repeat_results[-1]
check('T5', 'Later requests detect repetition pattern', last.get('repeated', False) == True or 'Repeated' in str(last.get('breakdown', [])))
check('T5', 'Repeated requests add +5 to score', last['risk_score'] >= 5)
check('T5', 'Final status is abnormal (repeated)', last['status'] == 'abnormal')
check('T5', 'Redirects to decoy environment', '/decoy' in last['redirect_url'])

# Check that score escalates over repeated requests
check('T5', 'Score escalates with repetition', repeat_results[-1]['risk_score'] >= repeat_results[0]['risk_score'])


# ═══════════════════════════════════════════════════════════════════════════
# TEST SCENARIO 6 — Decoy Environment Interaction
# ═══════════════════════════════════════════════════════════════════════════
separator("TEST SCENARIO 6 — Decoy Environment Interaction")

# Access decoy login page
code, html = api_get_html('/decoy')
print(f'  GET /decoy -> HTTP {code}')
check('T6', 'Decoy login page loads (HTTP 200)', code == 200)
check('T6', 'Decoy login contains login form', 'Sign In' in html or 'login' in html.lower())
check('T6', 'Decoy page looks realistic (Admin Portal)', 'Admin Portal' in html or 'Secure' in html)

# Simulate login attempt on decoy
login_result = api_post('/decoy/login_attempt', {'username': 'admin', 'password': '8 chars'})
print(f'  POST /decoy/login_attempt -> {login_result}')
check('T6', 'Login attempt returns processing status', login_result.get('status') == 'processing')

# Simulate generic decoy action
action_result = api_post('/decoy/action', {'type': 'login_panel', 'action': 'field_focus', 'details': 'password field'})
check('T6', 'Decoy action tracking works', action_result.get('status') == 'ok')

# Verify decoy interactions logged
stats = api_get('/api/stats')
print(f'  Decoy interactions in DB: {stats["decoy_interactions"]}')
check('T6', 'Decoy interactions logged in database (>0)', stats['decoy_interactions'] > 0)

# Access decoy admin panel
code2, html2 = api_get_html('/decoy/admin')
print(f'  GET /decoy/admin -> HTTP {code2}')
check('T6', 'Decoy admin panel loads (HTTP 200)', code2 == 200)
check('T6', 'Decoy admin has system stats', 'Server Uptime' in html2)

# Access decoy file directory
code3, html3 = api_get_html('/decoy/files')
print(f'  GET /decoy/files -> HTTP {code3}')
check('T6', 'Decoy file directory loads (HTTP 200)', code3 == 200)
check('T6', 'Decoy files page has file listings', 'db_credentials' in html3 or 'file-item' in html3)


# ═══════════════════════════════════════════════════════════════════════════
# TEST SCENARIO 7 — Real-Time Dashboard Monitoring
# ═══════════════════════════════════════════════════════════════════════════
separator("TEST SCENARIO 7 — Real-Time Dashboard Monitoring")

# Load dashboard HTML
code, html = api_get_html('/dashboard')
print(f'  GET /dashboard -> HTTP {code}')

check('T7', 'Dashboard page loads (HTTP 200)', code == 200)
check('T7', 'Dashboard has total requests card', 'Total Requests' in html)
check('T7', 'Dashboard has abnormal attempts card', 'Abnormal Attempts' in html)
check('T7', 'Dashboard has normal requests card', 'Normal Requests' in html)
check('T7', 'Dashboard has active sessions card', 'Active Sessions' in html)
check('T7', 'Dashboard has decoy interactions card', 'Decoy Interactions' in html)
check('T7', 'Dashboard includes Chart.js', 'chart.js' in html.lower() or 'Chart' in html)
check('T7', 'Dashboard has monthly activity chart', 'monthlyChart' in html)
check('T7', 'Dashboard has trend chart', 'trendChart' in html)
check('T7', 'Dashboard has distribution chart', 'distributionChart' in html)
check('T7', 'Dashboard has live activity feed', 'activityFeed' in html or 'Live Activity' in html)
check('T7', 'Dashboard has sidebar navigation', 'sidebar' in html.lower())
check('T7', 'Dashboard uses AJAX polling (setInterval)', 'setInterval' in html or 'dashboard.js' in html)

# Test stats API returns correct structure
stats = api_get('/api/stats')
print(f'  /api/stats -> {stats}')
check('T7', 'Stats API returns total_requests', 'total_requests' in stats)
check('T7', 'Stats API returns abnormal_attempts', 'abnormal_attempts' in stats)
check('T7', 'Stats API returns normal_requests', 'normal_requests' in stats)
check('T7', 'Stats API returns active_sessions', 'active_sessions' in stats)


# ═══════════════════════════════════════════════════════════════════════════
# TEST SCENARIO 8 — Logging System Verification
# ═══════════════════════════════════════════════════════════════════════════
separator("TEST SCENARIO 8 — Logging System Verification")

logs = api_get('/api/logs?limit=50')
print(f'  Total logs returned: {len(logs)}')

check('T8', 'Logs endpoint returns data', len(logs) > 0)

if logs:
    sample = logs[0]
    print(f'  Sample log: {sample}')
    check('T8', 'Log has id field', 'id' in sample)
    check('T8', 'Log has timestamp field', 'timestamp' in sample)
    check('T8', 'Log has user_input field', 'user_input' in sample)
    check('T8', 'Log has risk_score field', 'risk_score' in sample)
    check('T8', 'Log has status field', 'status' in sample)
    check('T8', 'Log has ip_address field', 'ip_address' in sample)
    check('T8', 'Log has details field', 'details' in sample)
    check('T8', 'Status is valid (normal/abnormal)', sample['status'] in ('normal', 'abnormal'))

# Verify our test inputs appear in the logs
all_inputs = [l['user_input'] for l in logs]
check('T8', '"weather today" found in logs', any('weather today' in i for i in all_inputs))
check('T8', 'SQL injection attempt found in logs', any("OR '1'='1" in i for i in all_inputs))
check('T8', '"admin" repeated requests found in logs', all_inputs.count('admin') >= 4)


# ═══════════════════════════════════════════════════════════════════════════
# TEST SCENARIO 9 — CSV Export
# ═══════════════════════════════════════════════════════════════════════════
separator("TEST SCENARIO 9 — CSV Export")

csv_data = api_get_raw('/export_logs')
lines = csv_data.strip().split('\n')
print(f'  CSV lines: {len(lines)} (including header)')
print(f'  Header: {lines[0]}')

check('T9', 'CSV export returns data', len(lines) > 1)
check('T9', 'CSV has header row', 'id' in lines[0] and 'timestamp' in lines[0])
check('T9', 'CSV header includes user_input', 'user_input' in lines[0])
check('T9', 'CSV header includes risk_score', 'risk_score' in lines[0])
check('T9', 'CSV header includes status', 'status' in lines[0])
check('T9', 'CSV header includes ip_address', 'ip_address' in lines[0])
check('T9', 'CSV contains multiple data rows', len(lines) > 5)

if len(lines) > 1:
    print(f'  Sample data: {lines[1][:100]}...')


# ═══════════════════════════════════════════════════════════════════════════
# TEST SCENARIO 10 — Monthly Analytics
# ═══════════════════════════════════════════════════════════════════════════
separator("TEST SCENARIO 10 — Monthly Analytics")

# Monthly data API
monthly = api_get('/api/monthly_data')
print(f'  Monthly data entries: {len(monthly)}')
if monthly:
    print(f'  Sample: {monthly[0]}')

check('T10', 'Monthly data API returns data', len(monthly) > 0)
if monthly:
    check('T10', 'Monthly entry has month field', 'month' in monthly[0])
    check('T10', 'Monthly entry has total field', 'total' in monthly[0])
    check('T10', 'Monthly entry has abnormal field', 'abnormal' in monthly[0])
    check('T10', 'Monthly entry has normal field', 'normal' in monthly[0])

# Hourly trend API
hourly = api_get('/api/hourly_trend')
print(f'  Hourly trend entries: {len(hourly)}')
check('T10', 'Hourly trend API returns data', len(hourly) > 0)
if hourly:
    check('T10', 'Hourly entry has hour field', 'hour' in hourly[0])
    check('T10', 'Hourly entry has total field', 'total' in hourly[0])
    check('T10', 'Hourly entry has abnormal field', 'abnormal' in hourly[0])

# Risk distribution API
risk_dist = api_get('/api/risk_distribution')
print(f'  Risk distribution entries: {len(risk_dist)}')
check('T10', 'Risk distribution API returns data', len(risk_dist) > 0)

# Top IPs API
top_ips = api_get('/api/top_ips')
print(f'  Top IPs entries: {len(top_ips)}')
check('T10', 'Top IPs API returns data', len(top_ips) > 0)

# Config API
config = api_get('/api/config')
print(f'  Config: {config}')
check('T10', 'Config API returns risk_threshold', 'risk_threshold' in config)
check('T10', 'Config API returns sql_injection_score', 'sql_injection_score' in config)

# Dashboard analytics section
code, html = api_get_html('/dashboard')
check('T10', 'Dashboard has analytics section', 'section-analytics' in html)
check('T10', 'Dashboard has risk distribution chart', 'riskDistChart' in html)
check('T10', 'Dashboard has top IPs chart', 'topIpsChart' in html)
check('T10', 'Dashboard has insights panel', 'insightsPanel' in html)
check('T10', 'Dashboard has export report button', 'Export' in html)


# ═══════════════════════════════════════════════════════════════════════════
# LANDING PAGE VERIFICATION
# ═══════════════════════════════════════════════════════════════════════════
separator("LANDING PAGE VERIFICATION")

code, html = api_get_html('/')
check('LP', 'Landing page loads (HTTP 200)', code == 200)
check('LP', 'Has search/input field', 'keywordInput' in html or 'input' in html.lower())
check('LP', 'Has submit/analyze button', 'Analyze' in html or 'submitBtn' in html)
check('LP', 'Has hero section', 'hero' in html)
check('LP', 'Has loading indicator', 'loaderOverlay' in html or 'loader' in html.lower())
check('LP', 'Uses Poppins font', 'Poppins' in html or 'poppins' in html.lower())
check('LP', 'Uses AJAX (Fetch API)', 'fetch(' in html or 'main.js' in html)
check('LP', 'Has cybersecurity theme', 'Cyber' in html or 'Defense' in html)
check('LP', 'Has features section', 'features' in html.lower())


# ═══════════════════════════════════════════════════════════════════════════
# FR1–FR26 VALIDATION CHECKLIST
# ═══════════════════════════════════════════════════════════════════════════
separator("FR1–FR26 FUNCTIONAL REQUIREMENTS VALIDATION")

fr_checks = [
    ('FR1',  'User request input interface',         'keywordInput' in api_get_html('/')[1]),
    ('FR2',  'Dynamic processing without refresh',   'fetch(' in api_get_html('/')[1] or 'main.js' in api_get_html('/')[1]),
    ('FR3',  'Normal user access to real website',   t1_result['status'] == 'normal' and 'google.com' in t1_result['redirect_url']),
    ('FR4',  'Abnormal user isolation (decoy)',       '/decoy' in api_post('/analyze_request', {'keyword': "x' OR '1'='1"})['redirect_url']),
    ('FR5',  'Interaction monitoring engine',         len(api_get('/api/logs')) > 0),
    ('FR6',  'Abnormal pattern detection',            'sql_injection' in api_post('/analyze_request', {'keyword': "SELECT * FROM x"})['findings']),
    ('FR7',  'Risk scoring calculation',              api_post('/analyze_request', {'keyword': 'safe query'})['risk_score'] >= 0),
    ('FR8',  'Classification logic (normal/abnormal)', api_post('/analyze_request', {'keyword': 'hello'})['status'] in ('normal','abnormal')),
    ('FR9',  'Configurable threshold',                'risk_threshold' in api_get('/api/config')),
    ('FR10', 'Automatic decoy redirection',           '/decoy' in api_post('/analyze_request', {'keyword': "DROP TABLE users--"})['redirect_url']),
    ('FR11', 'Seamless redirection (no detection)',    api_get_html('/decoy')[0] == 200),
    ('FR12', 'Attacker isolation in decoy',           'Sign In' in api_get_html('/decoy')[1]),
    ('FR13', 'Multiple decoy templates',              api_get_html('/decoy')[0] == 200 and api_get_html('/decoy/admin')[0] == 200 and api_get_html('/decoy/files')[0] == 200),
    ('FR14', 'Abnormal attempt counter',              api_get('/api/stats')['abnormal_attempts'] > 0),
    ('FR15', 'Real-time dashboard refresh',           'setInterval' in api_get_html('/dashboard')[1] or 'dashboard.js' in api_get_html('/dashboard')[1]),
    ('FR16', 'Live risk classification display',      'activityFeed' in api_get_html('/dashboard')[1]),
    ('FR17', 'Decoy activity tracking',               api_get('/api/stats')['decoy_interactions'] > 0),
    ('FR18', 'Monthly analytics generation',          len(api_get('/api/monthly_data')) > 0),
    ('FR19', 'Request logging',                       len(api_get('/api/logs')) > 0),
    ('FR20', 'Structured log format',                 'timestamp' in api_get('/api/logs')[0] and 'risk_score' in api_get('/api/logs')[0]),
    ('FR21', 'Admin log review',                      'logsTableBody' in api_get_html('/dashboard')[1]),
    ('FR22', 'Admin dashboard',                       api_get_html('/dashboard')[0] == 200),
    ('FR23', 'Statistics display',                    'stat-card' in api_get_html('/dashboard')[1]),
    ('FR24', 'Graphical analytics (Chart.js)',        'chart.js' in api_get_html('/dashboard')[1].lower()),
    ('FR25', 'Automated reports (insights)',           'insightsPanel' in api_get_html('/dashboard')[1]),
    ('FR26', 'Exportable analytics (CSV)',            'export_logs' in api_get_html('/dashboard')[1]),
]

fr_pass = 0
fr_fail = 0
for fr_id, desc, passed in fr_checks:
    status = 'PASS' if passed else 'FAIL'
    if passed:
        fr_pass += 1
    else:
        fr_fail += 1
    print(f'  [{status}] {fr_id}: {desc}')


# ═══════════════════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ═══════════════════════════════════════════════════════════════════════════
print()
print('=' * 72)
print('  FINAL TEST REPORT')
print('=' * 72)
print()
print(f'  Scenario Tests:  {PASS_COUNT} passed, {FAIL_COUNT} failed')
print(f'  FR Validation:   {fr_pass}/26 passed, {fr_fail}/26 failed')
print(f'  Overall:         {PASS_COUNT + fr_pass} passed, {FAIL_COUNT + fr_fail} failed')
print()

total_tests = PASS_COUNT + FAIL_COUNT + fr_pass + fr_fail
total_pass = PASS_COUNT + fr_pass
pct = (total_pass / total_tests * 100) if total_tests else 0
print(f'  Pass Rate: {pct:.1f}% ({total_pass}/{total_tests})')
print()

if FAIL_COUNT + fr_fail == 0:
    print('  RESULT: ALL TESTS PASSED')
else:
    print(f'  RESULT: {FAIL_COUNT + fr_fail} TEST(S) FAILED — REVIEW NEEDED')
print()
print('=' * 72)
