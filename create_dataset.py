import pandas as pd
examples = {
    'NORMAL': ['GET / HTTP/1.1', 'GET /index.html HTTP/1.1', 'POST /login user=admin&pass=123', 'GET /api/v1/health HTTP/1.1', 'User-Agent: Mozilla/5.0'],
    'SQL INJECTION': ["' OR 1=1 --", "admin' --", '1; DROP TABLE users', 'UNION SELECT username, password FROM users', "1' OR '1'='1"],
    'CROSS-SITE SCRIPTING (XSS)': ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', 'javascript:alert(\'XSS\')', 'onload=alert(1)'],
    'PATH TRAVERSAL': ['../../../../etc/passwd', '..\\..\\windows\\system32\\cmd.exe', '/etc/shadow'],
    'COMMAND INJECTION': ['; cat /etc/passwd', '| ping -c 4 127.0.0.1', '`whoami`']
}
data = []
for k, v in examples.items():
    for p in v:
        for _ in range(20):
            data.append({'payload': p, 'label': k})
pd.DataFrame(data).to_csv('datasets/web_payloads.csv', index=False)
print('Dataset created')
