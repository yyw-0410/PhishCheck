import requests

BASE = 'http://127.0.0.1:8000/api'

print('='*60)
print('COMPREHENSIVE MANUAL API TESTING')
print('='*60)

# 1. HEALTH CHECK
print('\n[1] Health Check')
r = requests.get(f'{BASE}/health')
print(f'    Status: {r.status_code} - {r.json()}')

r = requests.get(f'{BASE}/health/integrations')
print(f'    Integrations: {len(r.json())} services checked')

# 2. REGISTRATION
print('\n[2] User Registration')
r = requests.post(f'{BASE}/auth/register', json={
    'name': 'API Test User',
    'email': 'apitest999@gmail.com',
    'password': 'SecurePass1'
})
if r.status_code == 200:
    print(f'    Status: {r.status_code} - SUCCESS')
    data = r.json()
    token = data['session_token']
    print(f'    User ID: {data["user"]["id"]}')
else:
    print(f'    Status: {r.status_code} - {r.json().get("detail", r.json())}')
    # Try login if already exists
    r = requests.post(f'{BASE}/auth/login', json={
        'email': 'apitest999@gmail.com',
        'password': 'SecurePass1'
    })
    token = r.json().get('session_token', '')

# 3. LOGIN
print('\n[3] User Login')
r = requests.post(f'{BASE}/auth/login', json={
    'email': 'apitest999@gmail.com',
    'password': 'SecurePass1'
})
print(f'    Status: {r.status_code}')
if r.status_code == 200:
    token = r.json()['session_token']
    print('    Token received: Yes')

# 4. Validate Session
print('\n[4] Validate Session')
headers = {'Authorization': f'Bearer {token}'}
r = requests.post(f'{BASE}/auth/validate', headers=headers)
print(f'    Status: {r.status_code}')
print(f'    Valid: {r.json().get("valid")}')

# 5. Get Current User
print('\n[5] Get Current User (/me)')
r = requests.get(f'{BASE}/auth/me', headers=headers)
print(f'    Status: {r.status_code}')
if r.status_code == 200:
    print(f'    Email: {r.json().get("email")}')

# 6. AI Suggestions
print('\n[6] AI Suggestions')
r = requests.get(f'{BASE}/ai/suggestions')
print(f'    Status: {r.status_code}')
print(f'    Suggestions: {len(r.json())} available')

# 7. Logout
print('\n[7] Logout')
r = requests.post(f'{BASE}/auth/logout', headers=headers)
print(f'    Status: {r.status_code}')
print(f'    Message: {r.json().get("message")}')

# 8. Verify session invalid after logout
print('\n[8] Verify Session Invalid After Logout')
r = requests.post(f'{BASE}/auth/validate', headers=headers)
print(f'    Status: {r.status_code}')
print(f'    Valid: {r.json().get("valid")}')

print('\n' + '='*60)
print('ALL API TESTS COMPLETE')
print('='*60)
