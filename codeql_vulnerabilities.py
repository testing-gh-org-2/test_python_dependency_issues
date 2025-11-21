"""
Common Python Code Vulnerabilities for Testing
WARNING: This code contains intentional security vulnerabilities for testing.
DO NOT use in production!
"""
import os
import pickle
import hashlib
import sqlite3
import random
from flask import request, Flask

app = Flask(__name__)

# ========== COMMON PYTHON VULNERABILITIES ==========

# 1. Command Injection (CWE-78) - CRITICAL
@app.route('/execute')
def execute_command():
    """Command injection via os.system()"""
    user_input = request.args.get('cmd', '')
    os.system(user_input)  # Vulnerable - no sanitization
    return "Command executed"


# 2. SQL Injection (CWE-89) - CRITICAL
@app.route('/query_user')
def query_user():
    """SQL injection via string concatenation"""
    username = request.args.get('username', '')
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # Vulnerable - user input concatenated into query
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    result = cursor.fetchall()
    conn.close()
    return str(result)


# 3. Code Injection via eval() (CWE-94) - CRITICAL
@app.route('/calculate')
def calculate():
    """Code injection via eval()"""
    expr = request.args.get('expr', '1+1')
    result = eval(expr)  # Vulnerable - arbitrary code execution
    return f"Result: {result}"


# 4. Code Injection via exec() (CWE-94) - CRITICAL
@app.route('/exec_code')
def exec_code():
    """Code injection via exec()"""
    code = request.args.get('code', 'print("hello")')
    exec(code)  # Vulnerable - arbitrary code execution
    return "Code executed"


# 5. Unsafe Deserialization (CWE-502) - CRITICAL
@app.route('/load_data', methods=['POST'])
def load_data():
    """Pickle deserialization vulnerability"""
    data = request.data
    obj = pickle.loads(data)  # Vulnerable - unsafe deserialization
    return str(obj)


# 6. Path Traversal (CWE-22) - HIGH
@app.route('/read_file')
def read_file():
    """Path traversal vulnerability"""
    filename = request.args.get('file', 'readme.txt')
    # Vulnerable - no path sanitization
    with open(filename, 'r') as f:
        content = f.read()
    return content


# 7. Weak Cryptographic Hash (CWE-327) - MEDIUM
def hash_password(password):
    """Using weak MD5 for passwords"""
    # Vulnerable - MD5 is cryptographically broken
    return hashlib.md5(password.encode()).hexdigest()


# 8. Hardcoded Credentials (CWE-798) - HIGH
def connect_database():
    """Hardcoded database credentials"""
    DB_HOST = "localhost"
    DB_USER = "admin"
    DB_PASS = "Password123!"  # Vulnerable - hardcoded password
    return f"Connecting to {DB_HOST} as {DB_USER}"


# 9. Insecure Random Number Generation (CWE-330) - MEDIUM
def generate_token():
    """Using insecure random for security token"""
    # Vulnerable - random is not cryptographically secure
    return str(random.randint(100000, 999999))


# 10. Plain Text Password Storage (CWE-256) - HIGH
@app.route('/register', methods=['POST'])
def register():
    """Storing passwords in plain text"""
    username = request.form.get('username')
    password = request.form.get('password')
    # Vulnerable - password stored without hashing
    with open('users.txt', 'a') as f:
        f.write(f"{username}:{password}\n")
    return "User registered"


# 11. Unvalidated Redirect (CWE-601) - MEDIUM
@app.route('/redirect')
def redirect_url():
    """Open redirect vulnerability"""
    url = request.args.get('url', '/')
    # Vulnerable - no URL validation
    return f'<meta http-equiv="refresh" content="0; url={url}">'


# 12. Missing Input Validation (CWE-20) - MEDIUM
@app.route('/process')
def process_input():
    """No input validation"""
    data = request.args.get('data', '')
    # Vulnerable - no validation of input type or content
    result = int(data) * 100  # Could cause ValueError
    return str(result)


# 13. Race Condition (CWE-362) - MEDIUM
@app.route('/write_file')
def write_file():
    """Race condition in file operations"""
    filename = 'temp.txt'
    # Vulnerable - check and use not atomic
    if not os.path.exists(filename):
        with open(filename, 'w') as f:
            f.write('data')
    return "File written"


# 14. Information Exposure (CWE-209) - LOW
@app.route('/divide')
def divide():
    """Verbose error messages"""
    try:
        a = int(request.args.get('a', 10))
        b = int(request.args.get('b', 0))
        result = a / b
        return str(result)
    except Exception as e:
        # Vulnerable - exposes internal details
        import traceback
        return f"Error: {traceback.format_exc()}"


# 15. Improper Exception Handling (CWE-755) - LOW
@app.route('/parse_json')
def parse_json():
    """Catching all exceptions"""
    try:
        data = request.get_json()
        return str(data)
    except:  # Vulnerable - bare except clause
        return "Error"


# 16. Use of Assert in Production (CWE-617) - LOW
@app.route('/validate')
def validate():
    """Using assert for security checks"""
    is_admin = request.args.get('admin', 'false')
    # Vulnerable - assert can be disabled with -O flag
    assert is_admin == 'true', "Not admin"
    return "Admin access granted"


# 17. Timing Attack (CWE-208) - MEDIUM
@app.route('/check_password')
def check_password():
    """Timing attack on password comparison"""
    password = request.args.get('password', '')
    correct_password = "SecretPass123"
    # Vulnerable - direct string comparison reveals timing info
    if password == correct_password:
        return "Access granted"
    return "Access denied"


# 18. Missing Security Headers (CWE-693) - LOW
@app.route('/page')
def serve_page():
    """No security headers"""
    # Vulnerable - missing X-Frame-Options, CSP, etc.
    return "<h1>Welcome</h1>"


# 19. Insecure File Permissions (CWE-732) - MEDIUM
def create_sensitive_file():
    """Creating file with insecure permissions"""
    filename = 'sensitive.txt'
    with open(filename, 'w') as f:
        f.write('secret data')
    # Vulnerable - world-readable permissions
    os.chmod(filename, 0o777)


# 20. Missing Authorization Check (CWE-862) - HIGH
@app.route('/admin/delete_user')
def delete_user():
    """No authorization check"""
    user_id = request.args.get('id')
    # Vulnerable - no check if requester is admin
    return f"Deleted user {user_id}"


# ========== EMERGING & LATEST CODEQL VULNERABILITIES (2024-2025) ==========

# 21. AI/ML Model Injection (CWE-502) - CRITICAL
# New query added in CodeQL 2.15+ for AI/ML vulnerabilities
@app.route('/load_model', methods=['POST'])
def load_ml_model():
    """Unsafe ML model deserialization - PyTorch/TensorFlow"""
    import torch
    model_data = request.data
    # Vulnerable - untrusted model loading can execute arbitrary code
    model = torch.load(model_data)  # CodeQL: py/unsafe-deserialization
    return "Model loaded"


# 22. Server-Side Template Injection (SSTI) via Jinja2 (CWE-94) - CRITICAL
# Enhanced detection in CodeQL 2.14+
@app.route('/render_template')
def render_user_template():
    """SSTI vulnerability in Jinja2"""
    from flask import render_template_string
    template = request.args.get('template', 'Hello World')
    # Vulnerable - user input rendered as template
    return render_template_string(template)  # CodeQL: py/ssti


# 23. NoSQL Injection - MongoDB (CWE-943) - HIGH
# Added in CodeQL 2.16+ for NoSQL databases
@app.route('/find_user')
def find_user_nosql():
    """NoSQL injection in MongoDB queries"""
    from pymongo import MongoClient
    username = request.args.get('username', '')
    client = MongoClient('mongodb://localhost:27017/')
    db = client['mydb']
    # Vulnerable - unsanitized input in NoSQL query
    user = db.users.find_one({"username": username})  # CodeQL: py/nosql-injection
    return str(user)


# 24. Prototype Pollution via JSON (CWE-1321) - HIGH
# New pattern detection in CodeQL 2.15+
@app.route('/merge_config', methods=['POST'])
def merge_config():
    """Prototype pollution through recursive merge"""
    import json
    user_config = json.loads(request.data)
    default_config = {'setting': 'value'}
    
    def merge(target, source):
        # Vulnerable - no protection against __proto__ pollution
        for key, value in source.items():
            if isinstance(value, dict):
                target[key] = merge(target.get(key, {}), value)
            else:
                target[key] = value  # CodeQL: py/prototype-pollution
        return target
    
    result = merge(default_config, user_config)
    return str(result)


# 25. JWT Algorithm Confusion (CWE-347) - HIGH
# Enhanced detection in CodeQL 2.14+
@app.route('/verify_token')
def verify_jwt():
    """JWT algorithm confusion attack"""
    import jwt
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    # Vulnerable - accepts any algorithm, including 'none'
    decoded = jwt.decode(token, verify=False)  # CodeQL: py/jwt-missing-verification
    return str(decoded)


# 26. Path Traversal in ZIP Extraction (CWE-23) - HIGH
# Zip Slip vulnerability - enhanced detection in CodeQL 2.15+
@app.route('/extract_zip', methods=['POST'])
def extract_zip():
    """Zip Slip vulnerability"""
    import zipfile
    import io
    
    zip_data = request.data
    zip_file = zipfile.ZipFile(io.BytesIO(zip_data))
    
    for member in zip_file.namelist():
        # Vulnerable - no path validation before extraction
        zip_file.extract(member, '/tmp/uploads/')  # CodeQL: py/zipslip
    
    return "Extracted"


# 27. GraphQL Injection (CWE-89) - HIGH
# New query for GraphQL vulnerabilities in CodeQL 2.16+
@app.route('/graphql', methods=['POST'])
def graphql_query():
    """GraphQL injection vulnerability"""
    query = request.json.get('query', '')
    # Vulnerable - unsanitized GraphQL query
    result = f"{{ user(id: {query}) {{ name email }} }}"  # CodeQL: py/graphql-injection
    return result


# 28. LDAP Injection (CWE-90) - HIGH
# Enhanced pattern detection in CodeQL 2.14+
@app.route('/ldap_auth')
def ldap_authenticate():
    """LDAP injection via filter"""
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    # Vulnerable - unsanitized LDAP filter
    ldap_filter = f"(&(uid={username})(password={password}))"  # CodeQL: py/ldap-injection
    return f"Filter: {ldap_filter}"


# 29. XML Bomb (Billion Laughs) (CWE-776) - MEDIUM
# Enhanced XXE detection in CodeQL 2.15+
@app.route('/parse_large_xml', methods=['POST'])
def parse_xml_bomb():
    """XML bomb/billion laughs attack"""
    from xml.etree import ElementTree as ET
    xml_data = request.data
    # Vulnerable - no entity expansion limits
    tree = ET.fromstring(xml_data)  # CodeQL: py/xxe-local
    return "Parsed"


# 30. Regex Denial of Service (ReDoS) (CWE-1333) - MEDIUM
# Enhanced ReDoS detection in CodeQL 2.14+
@app.route('/validate_email')
def validate_email():
    """ReDoS via catastrophic backtracking"""
    import re
    email = request.args.get('email', '')
    # Vulnerable - exponential time complexity regex
    pattern = r'^([a-zA-Z0-9])(([\\.-]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$'
    result = re.match(pattern, email)  # CodeQL: py/polynomial-redos
    return str(result)


# 31. DNS Rebinding via SSRF (CWE-918) - HIGH
# Enhanced SSRF detection in CodeQL 2.16+
@app.route('/fetch_external')
def fetch_external_resource():
    """DNS rebinding attack via SSRF"""
    import urllib.request
    url = request.args.get('url', '')
    # Vulnerable - no DNS rebinding protection
    response = urllib.request.urlopen(url, timeout=30)  # CodeQL: py/full-ssrf
    return response.read()


# 32. Insecure Cryptographic Storage - AWS KMS (CWE-320) - HIGH
# Cloud-specific vulnerability detection in CodeQL 2.15+
@app.route('/encrypt_data')
def encrypt_with_weak_kms():
    """Weak encryption configuration"""
    import boto3
    data = request.args.get('data', '')
    kms = boto3.client('kms')
    # Vulnerable - using deprecated encryption algorithm
    response = kms.encrypt(
        KeyId='alias/mykey',
        Plaintext=data,
        EncryptionAlgorithm='RSAES_PKCS1_V1_5'  # Deprecated
    )  # CodeQL: py/weak-crypto-algorithm
    return str(response)


# 33. HTTP Response Splitting (CWE-113) - MEDIUM
# Enhanced header injection detection in CodeQL 2.14+
@app.route('/set_header')
def set_custom_header():
    """HTTP response splitting via header injection"""
    from flask import make_response
    custom_value = request.args.get('value', '')
    response = make_response("OK")
    # Vulnerable - unsanitized header value
    response.headers['Custom-Header'] = custom_value  # CodeQL: py/http-response-splitting
    return response


# 34. Insecure Randomness in Crypto Context (CWE-338) - MEDIUM
# Enhanced random detection in CodeQL 2.15+
@app.route('/generate_crypto_key')
def generate_weak_key():
    """Using non-cryptographic random for keys"""
    import random
    # Vulnerable - predictable key generation
    key = ''.join([str(random.randint(0, 9)) for _ in range(32)])  # CodeQL: py/insecure-randomness
    return key


# 35. CORS Misconfiguration (CWE-942) - MEDIUM
# New CORS detection in CodeQL 2.16+
@app.route('/api/data')
def api_with_bad_cors():
    """Overly permissive CORS configuration"""
    from flask import make_response
    response = make_response({"data": "sensitive"})
    origin = request.headers.get('Origin', '')
    # Vulnerable - reflects any origin without validation
    response.headers['Access-Control-Allow-Origin'] = origin  # CodeQL: py/cors-misconfiguration
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    return response


# 36. Unvalidated Forward/Redirect (CWE-601) - MEDIUM
# Enhanced open redirect detection in CodeQL 2.14+
@app.route('/forward')
def forward_request():
    """Unvalidated forward/redirect"""
    from flask import redirect
    target = request.args.get('next', '/')
    # Vulnerable - no allowlist validation
    return redirect(target)  # CodeQL: py/url-redirection


# 37. Log Injection (CWE-117) - MEDIUM
# New log injection detection in CodeQL 2.15+
@app.route('/log_event')
def log_user_input():
    """Log injection vulnerability"""
    import logging
    user_input = request.args.get('message', '')
    # Vulnerable - unvalidated input in logs
    logging.info(f"User message: {user_input}")  # CodeQL: py/log-injection
    return "Logged"


# 38. Improper Certificate Validation (CWE-295) - HIGH
# Enhanced TLS/SSL detection in CodeQL 2.16+
@app.route('/fetch_https')
def fetch_with_no_cert_validation():
    """Disabling SSL certificate verification"""
    import requests
    url = request.args.get('url', '')
    # Vulnerable - SSL verification disabled
    response = requests.get(url, verify=False)  # CodeQL: py/request-without-cert-validation
    return response.text


# 39. Sensitive Data in URL (CWE-598) - LOW
# New pattern detection in CodeQL 2.15+
@app.route('/process_payment')
def process_payment_with_sensitive_url():
    """Sensitive data in GET parameters"""
    # Vulnerable - sensitive data in URL (logged, cached, etc.)
    credit_card = request.args.get('cc', '')  # CodeQL: py/sensitive-data-in-url
    cvv = request.args.get('cvv', '')
    return f"Processing card ending in {credit_card[-4:]}"


# 40. Use of Hardcoded IV/Salt (CWE-329) - MEDIUM
# Enhanced crypto pattern detection in CodeQL 2.16+
@app.route('/encrypt_aes')
def encrypt_with_hardcoded_iv():
    """Hardcoded IV in encryption"""
    from Crypto.Cipher import AES
    data = request.args.get('data', '').encode()
    key = b'Sixteen byte key'
    # Vulnerable - hardcoded IV
    iv = b'1234567890123456'  # CodeQL: py/hardcoded-iv
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(data.ljust(16))
    return encrypted.hex()


# 41. XML External Entity via lxml (CWE-611) - HIGH
@app.route('/parse_lxml', methods=['POST'])
def parse_with_lxml():
    """XXE via lxml parser"""
    from lxml import etree
    xml_data = request.data
    parser = etree.XMLParser(resolve_entities=True)  # Vulnerable
    tree = etree.fromstring(xml_data, parser)
    return etree.tostring(tree).decode()


# 42. SQL Injection in ORM (CWE-89) - HIGH
@app.route('/orm_query')
def orm_sql_injection():
    """SQL injection via raw SQL in ORM"""
    from sqlalchemy import create_engine, text
    username = request.args.get('username', '')
    engine = create_engine('sqlite:///users.db')
    query = text(f"SELECT * FROM users WHERE name = '{username}'")  # Vulnerable
    with engine.connect() as conn:
        result = conn.execute(query)
    return str(list(result))


# 43. Insecure Direct Object Reference (CWE-639) - MEDIUM
@app.route('/get_document/<doc_id>')
def get_document(doc_id):
    """IDOR - no ownership check"""
    # Vulnerable - no check if user owns document
    with open(f'/documents/{doc_id}.txt', 'r') as f:
        return f.read()


# 44. Mass Assignment (CWE-915) - MEDIUM
@app.route('/update_profile', methods=['POST'])
def update_profile():
    """Mass assignment vulnerability"""
    user_data = request.json
    # Vulnerable - allows setting is_admin field
    user = {'name': user_data.get('name'), 
            'email': user_data.get('email'),
            'is_admin': user_data.get('is_admin', False)}  # Dangerous
    return str(user)


# 45. Server-Side Request Forgery via URL (CWE-918) - HIGH
@app.route('/proxy')
def proxy_request():
    """SSRF with no validation"""
    import urllib.request
    target = request.args.get('url', '')
    # Vulnerable - can access internal services
    req = urllib.request.Request(target)
    response = urllib.request.urlopen(req)
    return response.read()


# 46. Insecure Deserialization - YAML (CWE-502) - CRITICAL
@app.route('/load_yaml', methods=['POST'])
def load_yaml_unsafe():
    """Unsafe YAML loading"""
    import yaml
    data = request.data.decode()
    # Vulnerable - allows arbitrary object instantiation
    config = yaml.load(data, Loader=yaml.Loader)
    return str(config)


# 47. Buffer Overflow via ctypes (CWE-120) - HIGH
@app.route('/buffer_test')
def buffer_overflow():
    """Buffer overflow in C library call"""
    import ctypes
    user_input = request.args.get('data', '')
    buffer = ctypes.create_string_buffer(10)
    # Vulnerable - no bounds checking
    ctypes.memmove(buffer, user_input.encode(), len(user_input))
    return buffer.value.decode()


# 48. Use of GET for State-Changing Operations (CWE-650) - MEDIUM
@app.route('/delete_account')
def delete_account_get():
    """State-changing operation via GET"""
    user_id = request.args.get('id')
    # Vulnerable - GET should not modify state
    return f"Account {user_id} deleted"


# 49. Insufficient Session Expiration (CWE-613) - MEDIUM
@app.route('/create_session')
def create_long_session():
    """Session without expiration"""
    from flask import session
    session.permanent = True
    # Vulnerable - no session timeout
    session['user_id'] = request.args.get('user_id')
    return "Session created"


# 50. Cookie Without Secure Flag (CWE-614) - MEDIUM
@app.route('/set_cookie')
def set_insecure_cookie():
    """Cookie without secure flag"""
    from flask import make_response
    resp = make_response("Cookie set")
    # Vulnerable - can be intercepted over HTTP
    resp.set_cookie('session_id', '12345', secure=False)
    return resp


# 51. Session Fixation (CWE-384) - HIGH
@app.route('/login_session', methods=['POST'])
def login_with_fixation():
    """Session fixation vulnerability"""
    from flask import session
    username = request.form.get('username')
    # Vulnerable - doesn't regenerate session ID
    session['username'] = username
    return "Logged in"


# 52. Clickjacking (CWE-1021) - MEDIUM
@app.route('/frame_page')
def frameable_page():
    """Missing X-Frame-Options header"""
    # Vulnerable - can be framed by attacker
    return "<h1>Clickable Content</h1>"


# 53. Missing Content-Type Header (CWE-345) - LOW
@app.route('/json_response')
def json_without_content_type():
    """JSON without proper content-type"""
    # Vulnerable - browser may misinterpret
    return '{"data": "value"}'


# 54. Insecure File Upload Extension (CWE-434) - CRITICAL
@app.route('/upload', methods=['POST'])
def upload_any_file():
    """No file extension validation"""
    file = request.files['file']
    # Vulnerable - allows .php, .exe, etc.
    file.save(f'/uploads/{file.filename}')
    return "Uploaded"


# 55. Directory Listing Enabled (CWE-548) - LOW
@app.route('/files/<path:filename>')
def serve_file(filename):
    """Directory traversal in file serving"""
    from flask import send_from_directory
    # Vulnerable - may expose directory structure
    return send_from_directory('/var/www/files/', filename)


# 56. Cleartext Transmission of Sensitive Data (CWE-319) - HIGH
@app.route('/send_password')
def send_password_http():
    """Sending password over HTTP"""
    password = request.args.get('password')
    # Vulnerable - no HTTPS enforcement
    return f"Password received: {password}"


# 57. Improper Input Validation - Email (CWE-20) - MEDIUM
@app.route('/send_email')
def send_email_no_validation():
    """Email injection"""
    to = request.args.get('to', '')
    subject = request.args.get('subject', '')
    # Vulnerable - no email format validation
    return f"Sending to: {to}"


# 58. LDAP Injection via bind (CWE-90) - HIGH
@app.route('/ldap_bind')
def ldap_bind_injection():
    """LDAP bind injection"""
    username = request.args.get('username', '')
    password = request.args.get('password', '')
    # Vulnerable - unsanitized LDAP bind
    dn = f"uid={username},ou=users,dc=example,dc=com"
    return f"Binding to: {dn}"


# 59. XPath Injection (CWE-643) - HIGH
@app.route('/xpath_query')
def xpath_injection():
    """XPath injection vulnerability"""
    from lxml import etree
    username = request.args.get('username', '')
    xml = etree.parse('users.xml')
    # Vulnerable - XPath injection
    query = f"//user[username='{username}']"
    result = xml.xpath(query)
    return str(result)


# 60. Format String Vulnerability (CWE-134) - MEDIUM
@app.route('/format_log')
def format_string_vuln():
    """Format string vulnerability"""
    user_input = request.args.get('msg', '')
    # Vulnerable - user controls format string
    log_message = f"{user_input}"  # If used in C extensions
    return log_message


# 61. Integer Overflow (CWE-190) - MEDIUM
@app.route('/allocate_buffer')
def integer_overflow():
    """Integer overflow in size calculation"""
    size = int(request.args.get('size', '100'))
    count = int(request.args.get('count', '100'))
    # Vulnerable - no overflow check
    total_size = size * count
    buffer = bytearray(total_size)
    return f"Allocated {total_size} bytes"


# 62. Use After Free (CWE-416) - HIGH
@app.route('/cache_operation')
def use_after_free():
    """Simulated use-after-free"""
    cache = {}
    key = request.args.get('key', '')
    # Vulnerable pattern - accessing deleted reference
    if key in cache:
        del cache[key]
    return str(cache.get(key, 'None'))


# 63. Double Free (CWE-415) - HIGH
@app.route('/free_memory')
def double_free():
    """Double free simulation"""
    data = request.args.get('data', '')
    # Vulnerable - freeing same resource twice
    temp = bytearray(data.encode())
    del temp
    del temp  # Double free
    return "Freed"


# 64. Null Pointer Dereference (CWE-476) - MEDIUM
@app.route('/access_null')
def null_pointer():
    """Null pointer dereference"""
    obj = None
    if request.args.get('init') != 'true':
        obj = None
    # Vulnerable - accessing None
    return str(obj.value)  # AttributeError


# 65. Uninitialized Variable (CWE-457) - LOW
@app.route('/use_uninit')
def use_uninitialized():
    """Using uninitialized variable"""
    if request.args.get('flag') == 'true':
        result = "initialized"
    # Vulnerable - result may be uninitialized
    return result


# 66. Missing Error Handling (CWE-391) - LOW
@app.route('/risky_operation')
def no_error_handling():
    """Missing try-catch for critical operation"""
    # Vulnerable - no error handling
    value = int(request.args.get('num'))
    result = 100 / value
    return str(result)


# 67. Improper Resource Shutdown (CWE-404) - MEDIUM
@app.route('/open_file_leak')
def file_descriptor_leak():
    """File descriptor leak"""
    filename = request.args.get('file', 'data.txt')
    # Vulnerable - file not closed on exception
    f = open(filename, 'r')
    data = f.read()
    return data


# 68. Time-of-Check Time-of-Use (TOCTOU) (CWE-367) - MEDIUM
@app.route('/toctou')
def toctou_race():
    """TOCTOU race condition"""
    filename = request.args.get('file', 'temp.txt')
    # Vulnerable - check and use not atomic
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return f.read()
    return "Not found"


# 69. Insecure Temporary File (CWE-377) - MEDIUM
@app.route('/create_temp')
def insecure_temp_file():
    """Predictable temporary file"""
    import tempfile
    # Vulnerable - predictable temp file name
    temp_path = f"/tmp/upload_{request.remote_addr}.txt"
    with open(temp_path, 'w') as f:
        f.write("data")
    return temp_path


# 70. Weak Password Recovery (CWE-640) - MEDIUM
@app.route('/recover_password')
def weak_password_recovery():
    """Weak password recovery mechanism"""
    email = request.args.get('email', '')
    # Vulnerable - predictable token
    token = hashlib.md5(email.encode()).hexdigest()[:6]
    return f"Recovery token: {token}"


# 71. Username Enumeration (CWE-204) - LOW
@app.route('/check_user')
def username_enumeration():
    """Username enumeration via error messages"""
    username = request.args.get('username', '')
    if username == 'admin':
        return "User exists, password incorrect"
    return "User does not exist"


# 72. Account Lockout Not Implemented (CWE-307) - MEDIUM
@app.route('/login_no_lockout', methods=['POST'])
def login_without_lockout():
    """No account lockout mechanism"""
    username = request.form.get('username')
    password = request.form.get('password')
    # Vulnerable - unlimited login attempts
    return "Login failed"


# 73. Privilege Escalation (CWE-269) - CRITICAL
@app.route('/change_role')
def change_user_role():
    """Privilege escalation vulnerability"""
    user_id = request.args.get('user_id')
    role = request.args.get('role', 'user')
    # Vulnerable - no permission check
    return f"User {user_id} role changed to {role}"


# 74. Hardcoded Cryptographic Key (CWE-321) - HIGH
def encrypt_data_hardcoded():
    """Hardcoded encryption key"""
    from cryptography.fernet import Fernet
    # Vulnerable - hardcoded key
    key = b'ZmRzZmdkc2ZnZHNmZ2RzZmdkc2ZnZHNmZ2RzZmdkc2Y='
    f = Fernet(key)
    return f


# 75. Insufficient Entropy (CWE-331) - MEDIUM
@app.route('/generate_session_id')
def generate_weak_session_id():
    """Weak session ID generation"""
    import random
    # Vulnerable - insufficient entropy
    session_id = str(random.randint(1000, 9999))
    return session_id


# 76. Insecure SSL/TLS Configuration (CWE-327) - HIGH
def create_insecure_ssl_context():
    """Weak SSL/TLS configuration"""
    import ssl
    context = ssl.SSLContext(ssl.PROTOCOL_SSLv3)  # Vulnerable - SSLv3
    return context


# 77. Certificate Validation Disabled (CWE-295) - HIGH
@app.route('/https_no_verify')
def https_without_verification():
    """HTTPS without certificate verification"""
    import requests
    url = request.args.get('url', '')
    # Vulnerable - cert verification disabled
    r = requests.get(url, verify=False)
    return r.text


# 78. Weak Cipher Suite (CWE-326) - MEDIUM
def use_weak_cipher():
    """Using weak cipher algorithm"""
    from Crypto.Cipher import DES
    key = b'12345678'
    # Vulnerable - DES is weak
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher


# 79. Insufficient Key Length (CWE-326) - MEDIUM
def generate_short_key():
    """Insufficient key length"""
    from Crypto.Random import get_random_bytes
    # Vulnerable - too short for RSA
    key = get_random_bytes(8)
    return key


# 80. Predictable Seed (CWE-336) - MEDIUM
@app.route('/random_with_seed')
def predictable_random():
    """Predictable random due to seed"""
    import random
    # Vulnerable - predictable seed
    random.seed(12345)
    value = random.randint(1, 1000)
    return str(value)


# 81. SQL Injection in Stored Procedure (CWE-89) - HIGH
@app.route('/call_procedure')
def sql_injection_procedure():
    """SQL injection in stored procedure call"""
    import sqlite3
    user_id = request.args.get('id', '')
    conn = sqlite3.connect('db.sqlite')
    # Vulnerable - unsanitized procedure call
    query = f"CALL get_user('{user_id}')"
    conn.execute(query)
    return "Called"


# 82. OS Command Injection via subprocess (CWE-78) - CRITICAL
@app.route('/run_subprocess')
def subprocess_injection():
    """Command injection via subprocess"""
    import subprocess
    filename = request.args.get('file', '')
    # Vulnerable - shell=True with user input
    subprocess.call(f"cat {filename}", shell=True)
    return "Executed"


# 83. File Inclusion (CWE-98) - HIGH
@app.route('/include_file')
def remote_file_inclusion():
    """Remote file inclusion"""
    file_path = request.args.get('path', '')
    # Vulnerable - includes arbitrary files
    with open(file_path, 'r') as f:
        exec(f.read())
    return "Included"


# 84. CRLF Injection (CWE-93) - MEDIUM
@app.route('/log_crlf')
def crlf_injection():
    """CRLF injection in logs"""
    import logging
    user_input = request.args.get('data', '')
    # Vulnerable - CRLF not sanitized
    logging.info(user_input)
    return "Logged"


# 85. CSV Injection (CWE-1236) - MEDIUM
@app.route('/export_csv')
def csv_injection():
    """CSV injection vulnerability"""
    import csv
    import io
    user_data = request.args.get('data', '')
    output = io.StringIO()
    writer = csv.writer(output)
    # Vulnerable - formula injection in CSV
    writer.writerow([user_data])
    return output.getvalue()


# 86. MIME Sniffing (CWE-430) - LOW
@app.route('/download_file')
def download_without_content_type():
    """Missing X-Content-Type-Options"""
    from flask import send_file
    # Vulnerable - browser may sniff content type
    return send_file('document.pdf')


# 87. Insufficient Transport Layer Protection (CWE-319) - HIGH
@app.route('/mixed_content')
def mixed_content():
    """Loading resources over HTTP"""
    # Vulnerable - mixed content
    html = '<script src="http://example.com/script.js"></script>'
    return html


# 88. Weak Hashing for Integrity (CWE-328) - MEDIUM
@app.route('/checksum')
def weak_checksum():
    """Weak hash for integrity check"""
    data = request.args.get('data', '')
    # Vulnerable - MD5 for integrity
    checksum = hashlib.md5(data.encode()).hexdigest()
    return checksum


# 89. Information Leakage via Debug Info (CWE-215) - LOW
@app.route('/debug_info')
def leak_debug_info():
    """Leaking debug information"""
    # Vulnerable - exposes internal state
    return str(globals())


# 90. Server Banner Disclosure (CWE-200) - LOW
@app.route('/server_info')
def server_banner():
    """Server information disclosure"""
    import sys
    # Vulnerable - exposes server details
    return f"Python {sys.version}, Flask"


# 91. Memory Leak (CWE-401) - MEDIUM
global_cache = []
@app.route('/cache_data')
def memory_leak():
    """Memory leak via unbounded cache"""
    data = request.args.get('data', '') * 1000
    # Vulnerable - unbounded growth
    global_cache.append(data)
    return f"Cached {len(global_cache)} items"


# 92. Stack Overflow (CWE-121) - HIGH
@app.route('/recursive')
def stack_overflow():
    """Stack overflow via deep recursion"""
    depth = int(request.args.get('depth', '1000'))
    
    def recurse(n):
        if n > 0:
            return recurse(n - 1)  # Vulnerable - no limit
        return "Done"
    
    return recurse(depth)


# 93. Uncontrolled Memory Allocation (CWE-789) - HIGH
@app.route('/allocate_memory')
def uncontrolled_allocation():
    """Uncontrolled memory allocation"""
    size = int(request.args.get('size', '1000'))
    # Vulnerable - no size limit
    data = bytearray(size * 1024 * 1024)
    return f"Allocated {len(data)} bytes"


# 94. Improper Neutralization of Special Elements (CWE-75) - MEDIUM
@app.route('/process_special')
def special_chars_not_neutralized():
    """Special characters not neutralized"""
    data = request.args.get('data', '')
    # Vulnerable - special chars not handled
    return eval(f"'{data}'")


# 95. Missing Authentication (CWE-306) - CRITICAL
@app.route('/admin/panel')
def admin_panel_no_auth():
    """Admin panel without authentication"""
    # Vulnerable - no authentication check
    return "Admin Panel - Full Access"


# 96. Broken Access Control (CWE-284) - HIGH
@app.route('/user/<user_id>/data')
def access_user_data(user_id):
    """No access control check"""
    # Vulnerable - any user can access any user's data
    return f"Data for user {user_id}"


# 97. Insecure Default Configuration (CWE-1188) - MEDIUM
def create_app_with_defaults():
    """Insecure default configuration"""
    # Vulnerable - debug mode, weak secret
    app.config['DEBUG'] = True
    app.config['SECRET_KEY'] = 'default'
    return app


# 98. Exposure of Private Information (CWE-359) - MEDIUM
@app.route('/user_profile')
def expose_private_info():
    """Exposing private user information"""
    # Vulnerable - returns sensitive data
    user = {'name': 'John', 'ssn': '123-45-6789', 'password': 'secret'}
    return str(user)


# 99. Insufficient Randomness for Security (CWE-330) - MEDIUM
@app.route('/password_reset_token')
def weak_reset_token():
    """Weak password reset token"""
    import random
    import string
    # Vulnerable - predictable token
    token = ''.join(random.choices(string.ascii_letters, k=6))
    return token


# 100. Trust Boundary Violation (CWE-501) - MEDIUM
@app.route('/process_trusted_data')
def trust_boundary_violation():
    """Trusting user data without validation"""
    user_role = request.args.get('role', 'user')
    # Vulnerable - trusts user-provided role
    if user_role == 'admin':
        return "Admin access granted"
    return "User access"


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)