"""
Intelligent Cyber Defense Framework - Main Flask Application
Implements behavior-based intrusion detection, automated attack mitigation,
cyber deception, and real-time monitoring dashboards.
"""

from flask import (
    Flask, render_template, request, jsonify, Response, redirect, url_for
)
from database import (
    init_db, log_request, log_decoy_interaction, get_recent_logs,
    get_stats, get_monthly_data, get_hourly_trend, export_logs_csv,
    get_risk_distribution, get_top_ips, get_risk_config, update_risk_config
)
from risk_scoring import calculate_risk_score
import os
import re

app = Flask(__name__)
app.secret_key = os.urandom(32)

# Supported decoy websites (fixed set of 10)
SUPPORTED_SITES = [
    'amazon', 'netflix', 'flipkart', 'youtube', 'bookmyshow',
    'makemytrip', 'instagram', 'facebook', 'google', 'twitter'
]

# Real website URLs for normal (non-malicious) redirects
REAL_SITE_URLS = {
    'amazon': 'https://www.amazon.com',
    'netflix': 'https://www.netflix.com',
    'flipkart': 'https://www.flipkart.com',
    'youtube': 'https://www.youtube.com',
    'bookmyshow': 'https://www.bookmyshow.com',
    'makemytrip': 'https://www.makemytrip.com',
    'instagram': 'https://www.instagram.com',
    'facebook': 'https://www.facebook.com',
    'google': 'https://www.google.com',
    'twitter': 'https://twitter.com',
}

# Decoy template name per site (must match templates/decoy_<site>.html)
DECOY_TEMPLATES = { site: f'decoy_{site}.html' for site in SUPPORTED_SITES }


def extract_site_keyword(user_input):
    """
    Extract target website name from user input.
    Returns the first word/token if it matches a supported site (case-insensitive), else None.
    """
    if not user_input or not user_input.strip():
        return None
    # First token (split by whitespace or common separators)
    first = re.split(r'[\s;|&]+', user_input.strip())[0].lower()
    if not first:
        return None
    # Exact match
    if first in SUPPORTED_SITES:
        return first
    # Allow common prefixes (e.g. "amzn" -> amazon) – optional; for now exact only
    return None


# Initialize database on startup
init_db()


# ─── Landing Page ───────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Serve the main landing page with keyword input interface."""
    return render_template('index.html')


# ─── Request Analysis Endpoint ──────────────────────────────────────────────────

@app.route('/analyze_request', methods=['POST'])
def analyze_request():
    """
    Analyze user input: calculate risk score, log the request,
    and return classification result with redirect target.
    """
    data = request.get_json()
    if not data or 'keyword' not in data:
        return jsonify({'error': 'No keyword provided'}), 400

    user_input = data['keyword'].strip()
    if not user_input:
        return jsonify({'error': 'Empty keyword'}), 400

    # Limit input length to prevent abuse
    if len(user_input) > 2000:
        user_input = user_input[:2000]

    ip_address = request.remote_addr or '127.0.0.1'

    # Extract target website keyword (e.g. "amazon" from "amazon ; cat /etc/passwd")
    detected_site = extract_site_keyword(user_input)

    # Calculate risk score
    result = calculate_risk_score(user_input, ip_address)

    # Determine redirect target
    if result['status'] == 'normal':
        if detected_site and detected_site in REAL_SITE_URLS:
            redirect_url = REAL_SITE_URLS[detected_site]
        else:
            redirect_url = f"https://www.google.com/search?q={user_input}"
    else:
        # Malicious: redirect to brand decoy if supported, else generic decoy
        if detected_site and detected_site in SUPPORTED_SITES:
            redirect_url = url_for('decoy_site', site=detected_site)
        else:
            redirect_url = url_for('decoy_generic')

    redirect_destination = redirect_url if redirect_url.startswith('http') else request.host_url.rstrip('/') + redirect_url

    # Log the request (including detected site and redirect for analysis)
    log_request(
        user_input=user_input,
        risk_score=result['risk_score'],
        status=result['status'],
        ip_address=ip_address,
        details=result['details'],
        detected_site=detected_site or '',
        redirect_destination=redirect_destination
    )

    return jsonify({
        'status': result['status'],
        'risk_score': result['risk_score'],
        'threshold': result['threshold'],
        'details': result['details'],
        'breakdown': result['breakdown'],
        'findings': result['findings'],
        'redirect_url': redirect_url
    })


# ─── Admin Dashboard ────────────────────────────────────────────────────────────

@app.route('/dashboard')
def dashboard():
    """Serve the admin monitoring dashboard."""
    return render_template('dashboard.html')


# ─── API: Dashboard Statistics ──────────────────────────────────────────────────

@app.route('/api/stats')
def api_stats():
    """Return real-time dashboard statistics as JSON."""
    stats = get_stats()
    return jsonify(stats)


# ─── API: Recent Logs ──────────────────────────────────────────────────────────

@app.route('/api/logs')
def api_logs():
    """Return recent security logs as JSON."""
    limit = request.args.get('limit', 50, type=int)
    limit = min(limit, 500)  # Cap at 500
    logs = get_recent_logs(limit)
    return jsonify(logs)


# ─── API: Monthly Chart Data ───────────────────────────────────────────────────

@app.route('/api/monthly_data')
def api_monthly_data():
    """Return monthly activity data for charts."""
    return jsonify(get_monthly_data())


# ─── API: Hourly Trend Data ────────────────────────────────────────────────────

@app.route('/api/hourly_trend')
def api_hourly_trend():
    """Return hourly trend data for the last 24 hours."""
    return jsonify(get_hourly_trend())


# ─── API: Risk Distribution ────────────────────────────────────────────────────

@app.route('/api/risk_distribution')
def api_risk_distribution():
    """Return risk score distribution data."""
    return jsonify(get_risk_distribution())


# ─── API: Top IPs ──────────────────────────────────────────────────────────────

@app.route('/api/top_ips')
def api_top_ips():
    """Return top requesting IPs."""
    return jsonify(get_top_ips())


# ─── API: Risk Configuration ───────────────────────────────────────────────────

@app.route('/api/config', methods=['GET', 'POST'])
def api_config():
    """Get or update risk scoring configuration."""
    if request.method == 'GET':
        return jsonify(get_risk_config())

    data = request.get_json()
    if not data:
        return jsonify({'error': 'No data provided'}), 400

    allowed = {
        'long_keyword_score', 'special_chars_score', 'repeated_requests_score',
        'sql_injection_score', 'risk_threshold', 'long_keyword_length',
        'repeat_window_seconds', 'repeat_count_limit'
    }
    for key, value in data.items():
        if key in allowed:
            update_risk_config(key, value)

    return jsonify({'success': True, 'config': get_risk_config()})


# ─── CSV Export ─────────────────────────────────────────────────────────────────

@app.route('/export_logs')
def export_logs():
    """Export all security logs as a CSV file download."""
    csv_data = export_logs_csv()
    return Response(
        csv_data,
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=security_logs.csv'}
    )


# ─── Decoy Environments ────────────────────────────────────────────────────────

@app.route('/decoy')
def decoy_login():
    """Legacy: fake admin login decoy (kept for backward compatibility)."""
    ip = request.remote_addr or '127.0.0.1'
    log_decoy_interaction(ip, 'login_panel', 'page_view')
    return render_template('decoy_login.html')


@app.route('/decoy/generic')
def decoy_generic():
    """Generic decoy when malicious pattern detected but site not in supported list."""
    ip = request.remote_addr or '127.0.0.1'
    log_decoy_interaction(ip, 'generic', 'page_view')
    return render_template('decoy_generic.html')


@app.route('/decoy/<site>')
def decoy_site(site):
    """Serve brand-specific decoy page (amazon, netflix, youtube, etc.)."""
    site = site.lower()
    if site not in SUPPORTED_SITES or site not in DECOY_TEMPLATES:
        return redirect(url_for('decoy_generic'))
    ip = request.remote_addr or '127.0.0.1'
    log_decoy_interaction(ip, site, 'page_view')
    return render_template(DECOY_TEMPLATES[site], site_name=site)


@app.route('/decoy/admin')
def decoy_admin():
    """Serve the fake admin dashboard decoy page."""
    ip = request.remote_addr or '127.0.0.1'
    log_decoy_interaction(ip, 'admin_panel', 'page_view')
    return render_template('decoy_admin.html')


@app.route('/decoy/files')
def decoy_files():
    """Serve the fake file directory decoy page."""
    ip = request.remote_addr or '127.0.0.1'
    log_decoy_interaction(ip, 'file_directory', 'page_view')
    return render_template('decoy_files.html')


@app.route('/decoy/login_attempt', methods=['POST'])
def decoy_login_attempt():
    """Track login attempts on the decoy login page."""
    ip = request.remote_addr or '127.0.0.1'
    data = request.get_json() or {}
    username = data.get('username', '')[:100]
    log_decoy_interaction(ip, 'login_panel', 'login_attempt', f'username: {username}')
    return jsonify({'status': 'processing', 'message': 'Authenticating...'})


@app.route('/decoy/action', methods=['POST'])
def decoy_action():
    """Track any action within decoy environments."""
    ip = request.remote_addr or '127.0.0.1'
    data = request.get_json() or {}
    action = data.get('action', 'unknown')[:100]
    decoy_type = data.get('type', 'unknown')[:50]
    log_decoy_interaction(ip, decoy_type, action, str(data.get('details', ''))[:500])
    return jsonify({'status': 'ok'})


# ─── Run Server ─────────────────────────────────────────────────────────────────

if __name__ == '__main__':
    print("\n  +==================================================+")
    print("  |   Intelligent Cyber Defense Framework            |")
    print("  |   Running on http://127.0.0.1:5000               |")
    print("  |   Dashboard: http://127.0.0.1:5000/dashboard     |")
    print("  +==================================================+\n")
    app.run(debug=True, host='127.0.0.1', port=5000)
