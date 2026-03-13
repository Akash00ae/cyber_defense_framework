import re
s = "admin' OR '1'='1"
chars = re.findall(r'[^a-zA-Z0-9\s\.\-\_]', s)
print(f'Special chars: {chars}, count: {len(chars)}')
# score: sql_injection (+5) + excessive_special_chars if count > 3 (+3) + repeated if detected (+4)
