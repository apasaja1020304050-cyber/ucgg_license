from flask import Flask, request, jsonify
from flask_cors import CORS
from supabase import create_client, Client
import secrets
import string
from datetime import datetime, timedelta
import os

app = Flask(__name__)
CORS(app)

SUPABASE_URL = os.environ.get('SUPABASE_URL')
SUPABASE_KEY = os.environ.get('SUPABASE_SERVICE_KEY')
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

def generate_license_key(prefix='UCGG'):
    chars = string.ascii_uppercase + string.digits
    random_part = ''.join(secrets.choice(chars) for _ in range(20))
    return f"{prefix}-{random_part[:4]}-{random_part[4:8]}-{random_part[8:12]}-{random_part[12:16]}-{random_part[16:]}"

@app.route('/api/verify', methods=['POST'])
def verify_license():
    data = request.get_json()
    if not data or 'license_key' not in data:
        return jsonify({'valid': False, 'error': 'Missing license_key'}), 400
    
    license_key = data['license_key'].strip().upper()
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent', '')
    
    result = supabase.table('licenses').select('*').eq('license_key', license_key).eq('status', 'active').execute()
    
    if not result.data:
        supabase.table('license_logs').insert({'license_key': license_key, 'action': 'VERIFY_FAILED', 'details': f'Invalid key from {ip}'}).execute()
        return jsonify({'valid': False, 'error': 'Invalid license'}), 401
    
    license_data = result.data[0]
    
    if license_data.get('expires_at'):
        expires = datetime.fromisoformat(license_data['expires_at'].replace('Z', '+00:00'))
        if expires < datetime.now():
            supabase.table('licenses').update({'status': 'expired'}).eq('license_key', license_key).execute()
            return jsonify({'valid': False, 'error': 'License expired'}), 401
    
    supabase.table('licenses').update({'last_used': datetime.now().isoformat(), 'used_devices': license_data.get('used_devices', 0) + 1}).eq('license_key', license_key).execute()
    
    supabase.table('license_usage').insert({'license_key': license_key, 'ip_address': ip, 'user_agent': user_agent}).execute()
    supabase.table('license_logs').insert({'license_key': license_key, 'action': 'VERIFIED', 'details': f'From IP: {ip}'}).execute()
    
    return jsonify({'valid': True, 'license_key': license_data['license_key'], 'expires_at': license_data.get('expires_at'), 'max_devices': license_data.get('max_devices', 5), 'used_devices': license_data.get('used_devices', 0) + 1, 'owner': license_data.get('owner', 'Unknown')})

@app.route('/api/licenses', methods=['GET'])
def get_licenses():
    auth = request.headers.get('X-Admin-Key')
    if auth != os.environ.get('ADMIN_KEY'):
        return jsonify({'error': 'Unauthorized'}), 401
    result = supabase.table('licenses').select('*').order('created_at', desc=True).execute()
    return jsonify(result.data)

@app.route('/api/licenses/create', methods=['POST'])
def create_license():
    auth = request.headers.get('X-Admin-Key')
    if auth != os.environ.get('ADMIN_KEY'):
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    days = int(data.get('days', 30))
    max_devices = int(data.get('max_devices', 5))
    owner = data.get('owner', '')
    notes = data.get('notes', '')
    license_key = generate_license_key()
    expires_at = (datetime.now() + timedelta(days=days)).isoformat()
    supabase.table('licenses').insert({'license_key': license_key, 'expires_at': expires_at, 'max_devices': max_devices, 'owner': owner, 'notes': notes}).execute()
    supabase.table('license_logs').insert({'license_key': license_key, 'action': 'CREATED', 'details': f'By admin, expires in {days} days'}).execute()
    return jsonify({'success': True, 'license_key': license_key, 'expires_at': expires_at})

@app.route('/api/licenses/toggle/<license_key>', methods=['POST'])
def toggle_license(license_key):
    auth = request.headers.get('X-Admin-Key')
    if auth != os.environ.get('ADMIN_KEY'):
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    status = data.get('status', 'disabled')
    supabase.table('licenses').update({'status': status}).eq('license_key', license_key).execute()
    supabase.table('license_logs').insert({'license_key': license_key, 'action': f'STATUS_{status.upper()}', 'details': f'License {status}'}).execute()
    return jsonify({'success': True})

@app.route('/api/licenses/extend/<license_key>', methods=['POST'])
def extend_license(license_key):
    auth = request.headers.get('X-Admin-Key')
    if auth != os.environ.get('ADMIN_KEY'):
        return jsonify({'error': 'Unauthorized'}), 401
    data = request.get_json()
    days = int(data.get('days', 30))
    result = supabase.table('licenses').select('expires_at').eq('license_key', license_key).execute()
    if result.data:
        current_expires = result.data[0].get('expires_at')
        if current_expires:
            expires = datetime.fromisoformat(current_expires.replace('Z', '+00:00'))
            if expires < datetime.now():
                expires = datetime.now()
            new_expires = expires + timedelta(days=days)
        else:
            new_expires = datetime.now() + timedelta(days=days)
    else:
        new_expires = datetime.now() + timedelta(days=days)
    supabase.table('licenses').update({'expires_at': new_expires.isoformat(), 'status': 'active'}).eq('license_key', license_key).execute()
    supabase.table('license_logs').insert({'license_key': license_key, 'action': 'EXTENDED', 'details': f'Added {days} days'}).execute()
    return jsonify({'success': True, 'new_expires': new_expires.isoformat()})

@app.route('/api/licenses/delete/<license_key>', methods=['DELETE'])
def delete_license(license_key):
    auth = request.headers.get('X-Admin-Key')
    if auth != os.environ.get('ADMIN_KEY'):
        return jsonify({'error': 'Unauthorized'}), 401
    supabase.table('licenses').delete().eq('license_key', license_key).execute()
    supabase.table('license_logs').insert({'license_key': license_key, 'action': 'DELETED', 'details': 'License removed'}).execute()
    return jsonify({'success': True})

@app.route('/api/stats', methods=['GET'])
def get_stats():
    auth = request.headers.get('X-Admin-Key')
    if auth != os.environ.get('ADMIN_KEY'):
        return jsonify({'error': 'Unauthorized'}), 401
    total = supabase.table('licenses').select('count', count='exact').execute()
    active = supabase.table('licenses').select('count', count='exact').eq('status', 'active').execute()
    expired = supabase.table('licenses').select('count', count='exact').eq('status', 'expired').execute()
    disabled = supabase.table('licenses').select('count', count='exact').eq('status', 'disabled').execute()
    return jsonify({'total': total.count, 'active': active.count, 'expired': expired.count, 'disabled': disabled.count})

@app.route('/')
def index():
    return jsonify({'name': 'UCGG License API', 'version': '1.0', 'endpoints': {'verify': 'POST /api/verify', 'licenses': 'GET /api/licenses', 'create': 'POST /api/licenses/create', 'toggle': 'POST /api/licenses/toggle/<key>', 'extend': 'POST /api/licenses/extend/<key>', 'delete': 'DELETE /api/licenses/delete/<key>', 'stats': 'GET /api/stats'}})
