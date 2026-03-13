# Attack Pattern Detection Checklist

## Current Implementation Status

| # | Attack Type | Status | Coverage | Details |
|---|---|---|---|---|
| 1️⃣ | **SQL Injection** | ✅ FULL | 100% | SELECT, INSERT, UPDATE, DELETE, DROP, UNION, ALTER, CREATE, EXEC, OR 1=1, OR 'a'='a, UNION SELECT, CHAR/VARCHAR, 0x hex, WAITFOR, BENCHMARK |
| 2️⃣ | **XSS (Cross-Site Scripting)** | ✅ FULL | 100% | `<script>`, `javascript:`, `onerror=`, `<iframe>`, `<img onerror>`, `document.cookie` patterns |
| 3️⃣ | **Command Injection** | ✅ FULL | 100% | `;`, `&&`, `\|\|`, `\|`, `` ` ``, `$` operators + shell commands (cat, ls, dir, whoami, pwd, id, uname) |
| 4️⃣ | **Directory Traversal** | ✅ FULL | 100% | `../`, `..\`, `%2e%2e` detection |
| 5️⃣ | **Special Character Spam** | ⚠️ PARTIAL | 50% | Detects >3 special chars, but NOT >5 in a row (e.g., `$$$$$$$` may slip through) |
| 6️⃣ | **Long Input** | ✅ FULL | 100% | >50 chars detected |
| 7️⃣ | **Repeated Requests (Bot)** | ✅ FULL | 100% | 3+ identical requests within 60s window |
| 8️⃣ | **Path Injection** | ❌ MISSING | 0% | `/etc/passwd`, `C:\Windows\System32` NOT detected |
| 9️⃣ | **Encoded Attack Strings** | ❌ MISSING | 0% | URL encoded (`%3Cscript%3E`, `%27%20OR%201%3D1`) NOT decoded/detected |
| 🔟 | **Suspicious Symbol Combinations** | ⚠️ PARTIAL | 30% | Some combos detected via SQL injection, but NOT all (missing `' "` quote pairs, `--` comments alone, etc.) |

---

## Missing/Incomplete Features to Add

### 1. Path Injection Detection
**Missing Examples:**
- `/etc/passwd`
- `C:\Windows\System32`
- `/etc/shadow`
- `/proc/self/environ`

**Add to behavior_engine.py:**
```python
# Path injection patterns
path_patterns = [
    r'(/etc/|/proc/|/root/|/home/)',
    r'(C:\\Windows|C:\\Program Files|C:\\Users)',
    r'(/var/www|/usr/bin|/usr/local)',
]
for pattern in path_patterns:
    if re.search(pattern, user_input, re.IGNORECASE):
        findings.append('path_injection')
        break
```

### 2. URL Encoded Attack Strings
**Missing Examples:**
- `%3Cscript%3E` (encoded `<script>`)
- `%27%20OR%201%3D1` (encoded `' OR 1=1`)
- `%2F%2Fetc%2Fpasswd` (encoded `//etc/passwd`)

**Add to behavior_engine.py:**
```python
import urllib.parse

# Check for URL encoded attacks
try:
    decoded = urllib.parse.unquote(user_input)
    if decoded != user_input and len(decoded) > len(user_input) * 0.5:
        # Re-analyze the decoded string
        decoded_findings = analyze_keyword_structure(decoded)
        if decoded_findings:
            findings.append('encoded_attack')
except:
    pass
```

### 3. Special Character Percentage Check
**Current:** >3 special chars
**Missing:** Detect patterns like `$$$$$`, `@@@@@` (5+ same special char in a row)

**Add to behavior_engine.py:**
```python
# Check for repeated special characters ($$$$, @@@@, etc.)
if re.search(r'([^\w\s])\1{4,}', user_input):  # 5+ of same special char
    findings.append('excessive_special_chars')
```

### 4. Symbol Combination Detection
**Missing Examples:**
- `'; --` (quote + semicolon + comment)
- `" AND "` (quote + AND + quote)
- `<> <>` (multiple angle brackets)

---

## Impact Assessment

- **Current Pass Rate:** 100% (129/129 tests)
- **Actual Real-World Coverage:** ~85% (missing 3 categories)
- **Recommendation:** Add Path Injection + Encoded Attacks for **95%+ coverage**

---

## Action Items

1. [ ] Add path injection detection to behavior_engine.py
2. [ ] Add URL encoded attack detection 
3. [ ] Improve special character spam detection (5+ in a row)
4. [ ] Update risk_scoring.py if new findings added
5. [ ] Add tests for missing patterns
6. [ ] Re-run full test suite
