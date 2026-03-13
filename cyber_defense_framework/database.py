"""
Database Module - Intelligent Cyber Defense Framework
Handles SQLite database operations for security logging and analytics.
"""

import sqlite3
import os
from datetime import datetime, timedelta
import csv
import io

DATABASE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database')
DATABASE_PATH = os.path.join(DATABASE_DIR, 'security_logs.db')


def get_db_connection():
    """Create and return a database connection with row factory."""
    os.makedirs(DATABASE_DIR, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db():
    """Initialize database tables."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Main security logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            user_input TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('normal', 'abnormal')),
            ip_address TEXT NOT NULL,
            details TEXT DEFAULT ''
        )
    ''')

    # Decoy interaction tracking table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS decoy_interactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            ip_address TEXT NOT NULL,
            decoy_type TEXT NOT NULL,
            action TEXT NOT NULL,
            data TEXT DEFAULT ''
        )
    ''')

    # Risk configuration table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS risk_config (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            param_name TEXT UNIQUE NOT NULL,
            param_value INTEGER NOT NULL
        )
    ''')

    # Insert default risk config if not exists
    defaults = [
        ('long_keyword_score', 2),
        ('special_chars_score', 3),
        ('repeated_requests_score', 5),
        ('sql_injection_score', 5),
        ('risk_threshold', 5),
        ('long_keyword_length', 50),
        ('repeat_window_seconds', 60),
        ('repeat_count_limit', 3),
    ]
    for name, value in defaults:
        cursor.execute(
            'INSERT OR IGNORE INTO risk_config (param_name, param_value) VALUES (?, ?)',
            (name, value)
        )

    conn.commit()
    conn.close()


def get_risk_config():
    """Retrieve all risk configuration parameters as a dictionary."""
    conn = get_db_connection()
    rows = conn.execute('SELECT param_name, param_value FROM risk_config').fetchall()
    conn.close()
    return {row['param_name']: row['param_value'] for row in rows}


def update_risk_config(param_name, param_value):
    """Update a risk configuration parameter."""
    conn = get_db_connection()
    conn.execute(
        'UPDATE risk_config SET param_value = ? WHERE param_name = ?',
        (int(param_value), param_name)
    )
    conn.commit()
    conn.close()


def log_request(user_input, risk_score, status, ip_address, details=''):
    """Log an access request to the database."""
    conn = get_db_connection()
    conn.execute(
        '''INSERT INTO security_logs (timestamp, user_input, risk_score, status, ip_address, details)
           VALUES (?, ?, ?, ?, ?, ?)''',
        (datetime.now().isoformat(), user_input, risk_score, status, ip_address, details)
    )
    conn.commit()
    conn.close()


def log_decoy_interaction(ip_address, decoy_type, action, data=''):
    """Log interactions within decoy environments."""
    conn = get_db_connection()
    conn.execute(
        '''INSERT INTO decoy_interactions (timestamp, ip_address, decoy_type, action, data)
           VALUES (?, ?, ?, ?, ?)''',
        (datetime.now().isoformat(), ip_address, decoy_type, action, data)
    )
    conn.commit()
    conn.close()


def get_recent_logs(limit=50):
    """Retrieve recent security logs."""
    conn = get_db_connection()
    rows = conn.execute(
        'SELECT * FROM security_logs ORDER BY id DESC LIMIT ?', (limit,)
    ).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_all_logs():
    """Retrieve all security logs for export."""
    conn = get_db_connection()
    rows = conn.execute('SELECT * FROM security_logs ORDER BY id DESC').fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_stats():
    """Calculate dashboard statistics."""
    conn = get_db_connection()
    cursor = conn.cursor()

    total = cursor.execute('SELECT COUNT(*) FROM security_logs').fetchone()[0]
    abnormal = cursor.execute(
        "SELECT COUNT(*) FROM security_logs WHERE status = 'abnormal'"
    ).fetchone()[0]
    normal = cursor.execute(
        "SELECT COUNT(*) FROM security_logs WHERE status = 'normal'"
    ).fetchone()[0]

    # Active sessions: unique IPs in the last 15 minutes
    fifteen_min_ago = (datetime.now() - timedelta(minutes=15)).isoformat()
    active = cursor.execute(
        'SELECT COUNT(DISTINCT ip_address) FROM security_logs WHERE timestamp > ?',
        (fifteen_min_ago,)
    ).fetchone()[0]

    # Decoy interactions count
    decoy_count = cursor.execute('SELECT COUNT(*) FROM decoy_interactions').fetchone()[0]

    conn.close()
    return {
        'total_requests': total,
        'abnormal_attempts': abnormal,
        'normal_requests': normal,
        'active_sessions': active,
        'decoy_interactions': decoy_count
    }


def get_monthly_data():
    """Get monthly abnormal activity data for chart visualization."""
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT strftime('%Y-%m', timestamp) as month,
               COUNT(*) as total,
               SUM(CASE WHEN status = 'abnormal' THEN 1 ELSE 0 END) as abnormal,
               SUM(CASE WHEN status = 'normal' THEN 1 ELSE 0 END) as normal
        FROM security_logs
        GROUP BY month
        ORDER BY month DESC
        LIMIT 12
    ''').fetchall()
    conn.close()
    result = [dict(row) for row in rows]
    result.reverse()
    return result


def get_hourly_trend():
    """Get hourly request trend for the last 24 hours."""
    conn = get_db_connection()
    twenty_four_hours_ago = (datetime.now() - timedelta(hours=24)).isoformat()
    rows = conn.execute('''
        SELECT strftime('%H', timestamp) as hour,
               COUNT(*) as total,
               SUM(CASE WHEN status = 'abnormal' THEN 1 ELSE 0 END) as abnormal
        FROM security_logs
        WHERE timestamp > ?
        GROUP BY hour
        ORDER BY hour
    ''', (twenty_four_hours_ago,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_recent_requests_by_ip(ip_address, window_seconds=60):
    """Count recent requests from a specific IP within a time window."""
    conn = get_db_connection()
    cutoff = (datetime.now() - timedelta(seconds=window_seconds)).isoformat()
    count = conn.execute(
        'SELECT COUNT(*) FROM security_logs WHERE ip_address = ? AND timestamp > ?',
        (ip_address, cutoff)
    ).fetchone()[0]
    conn.close()
    return count


def export_logs_csv():
    """Export all logs as CSV string."""
    logs = get_all_logs()
    output = io.StringIO()
    if logs:
        writer = csv.DictWriter(output, fieldnames=logs[0].keys())
        writer.writeheader()
        writer.writerows(logs)
    return output.getvalue()


def get_risk_distribution():
    """Get risk score distribution for analytics."""
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT
            CASE
                WHEN risk_score BETWEEN 0 AND 2 THEN 'Low (0-2)'
                WHEN risk_score BETWEEN 3 AND 5 THEN 'Medium (3-5)'
                WHEN risk_score BETWEEN 6 AND 9 THEN 'High (6-9)'
                ELSE 'Critical (10+)'
            END as category,
            COUNT(*) as count
        FROM security_logs
        GROUP BY category
        ORDER BY MIN(risk_score)
    ''').fetchall()
    conn.close()
    return [dict(row) for row in rows]


def get_top_ips(limit=10):
    """Get top IPs by request count."""
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT ip_address, COUNT(*) as request_count,
               SUM(CASE WHEN status = 'abnormal' THEN 1 ELSE 0 END) as abnormal_count
        FROM security_logs
        GROUP BY ip_address
        ORDER BY request_count DESC
        LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return [dict(row) for row in rows]
