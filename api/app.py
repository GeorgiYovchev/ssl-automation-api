"""
SSL Certificate Automation API
Flask-based API with web UI for uploading certificates and triggering deployments
"""

import os
import re
import hashlib
import tempfile
import subprocess
import logging
from pathlib import Path
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, request, jsonify, render_template, Response
from werkzeug.utils import secure_filename
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Configuration
app.config.update(
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,  # 16MB max upload
    UPLOAD_FOLDER=os.environ.get('UPLOAD_FOLDER', '/tmp/ssl-uploads'),
    GITLAB_URL=os.environ.get('GITLAB_URL', 'https://gitlab.example.com'),
    GITLAB_PROJECT_ID=os.environ.get('GITLAB_PROJECT_ID', ''),
    GITLAB_TOKEN=os.environ.get('GITLAB_TOKEN', ''),
    GITLAB_BRANCH=os.environ.get('GITLAB_BRANCH', 'main'),
    API_KEY=os.environ.get('API_KEY', ''),  # Optional API key for protection
    SECRET_KEY=os.environ.get('SECRET_KEY', 'change-me-in-production'),
)

# Ensure upload folder exists
Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)


# Authentication (optional)

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = app.config['API_KEY']
        if api_key:
            provided_key = request.headers.get('X-API-Key') or request.args.get('api_key')
            if provided_key != api_key:
                return jsonify({'error': 'Invalid or missing API key'}), 401
        return f(*args, **kwargs)
    return decorated


# Certificate Validation

def validate_certificate(cert_data: bytes) -> dict:
    """Validate certificate and extract information"""
    try:
        cert = x509.load_pem_x509_certificate(cert_data)
    except Exception:
        try:
            cert = x509.load_der_x509_certificate(cert_data)
        except Exception as e:
            return {'valid': False, 'error': f'Invalid certificate format: {e}'}
    
    now = datetime.now(timezone.utc)
    not_after = cert.not_valid_after_utc
    days_remaining = (not_after - now).days
    
    # Extract domains
    domains = []
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            domains.append(attr.value)
    try:
        san = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san.value:
            if isinstance(name, x509.DNSName) and name.value not in domains:
                domains.append(name.value)
    except Exception:
        pass
    
    return {
        'valid': True,
        'subject': cert.subject.rfc4514_string(),
        'issuer': cert.issuer.rfc4514_string(),
        'not_before': cert.not_valid_before_utc.isoformat(),
        'not_after': cert.not_valid_after_utc.isoformat(),
        'days_remaining': days_remaining,
        'domains': domains,
        'expired': days_remaining < 0,
        'expiring_soon': 0 <= days_remaining <= 30,
    }


def validate_private_key(key_data: bytes) -> dict:
    """Validate private key"""
    try:
        key = serialization.load_pem_private_key(key_data, password=None)
        return {'valid': True, 'key_size': key.key_size if hasattr(key, 'key_size') else None}
    except Exception as e:
        return {'valid': False, 'error': f'Invalid private key: {e}'}


def verify_key_pair(cert_data: bytes, key_data: bytes) -> bool:
    """Verify certificate and key match"""
    try:
        cert = x509.load_pem_x509_certificate(cert_data)
        key = serialization.load_pem_private_key(key_data, password=None)
        
        cert_pub = cert.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_pub = key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return cert_pub == key_pub
    except Exception:
        return False


def is_valid_domain(domain: str) -> tuple[bool, str]:
    """
    Validate domain name according to RFC 1035 and common standards
    Returns (is_valid, error_message)
    """
    if not domain:
        return False, "Domain cannot be empty"
    
    # Max length check (253 chars for full domain)
    if len(domain) > 253:
        return False, f"Domain too long ({len(domain)} chars, max 253)"
    
    # Must contain at least one dot (TLD required)
    if '.' not in domain:
        return False, "Domain must have at least one dot (e.g., example.com)"
    
    # Cannot start or end with dot or hyphen
    if domain.startswith('.') or domain.endswith('.'):
        return False, "Domain cannot start or end with a dot"
    if domain.startswith('-') or domain.endswith('-'):
        return False, "Domain cannot start or end with a hyphen"
    
    # Split into labels
    labels = domain.split('.')
    
    # TLD validation (last part)
    tld = labels[-1]
    if len(tld) < 2:
        return False, f"Invalid TLD: '{tld}' (must be at least 2 characters)"
    if tld.isdigit():
        return False, f"TLD cannot be only numbers: '{tld}'"
    
    # Check each label
    for label in labels:
        if not label:
            return False, "Domain contains empty label (consecutive dots)"
        
        if len(label) > 63:
            return False, f"Label '{label}' too long ({len(label)} chars, max 63)"
        
        if label.startswith('-') or label.endswith('-'):
            return False, f"Label '{label}' cannot start or end with hyphen"
        
        # Only allow: a-z, 0-9, hyphen (and underscore for some DNS records)
        if not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', label) and len(label) > 1:
            # Check for invalid characters
            invalid_chars = re.findall(r'[^a-z0-9-]', label)
            if invalid_chars:
                return False, f"Label '{label}' contains invalid characters: {set(invalid_chars)}"
            return False, f"Invalid label format: '{label}'"
        
        # Single char label must be alphanumeric
        if len(label) == 1 and not label.isalnum():
            return False, f"Single character label must be alphanumeric: '{label}'"
    
    return True, ""


def parse_domains(domains_input: str) -> tuple[list, list]:
    """
    Parse domains from various formats (comma, newline, space separated)
    Returns (valid_domains, errors)
    """
    # Replace common separators with newlines
    normalized = re.sub(r'[,;\s]+', '\n', domains_input)
    
    domains = []
    errors = []
    
    for line in normalized.split('\n'):
        domain = line.strip().lower()
        
        if not domain:
            continue
            
        # Skip comments
        if domain.startswith('#'):
            continue
        
        # Validate domain
        is_valid, error = is_valid_domain(domain)
        
        if is_valid:
            if domain not in domains:
                domains.append(domain)
        else:
            errors.append(f"'{domain}': {error}")
    
    return domains, errors


# GitLab Integration

def trigger_gitlab_pipeline(cert_content: str, key_content: str, domains: list) -> dict:
    """Trigger GitLab pipeline with certificate files"""
    import requests
    
    gitlab_url = app.config['GITLAB_URL']
    project_id = app.config['GITLAB_PROJECT_ID']
    token = app.config['GITLAB_TOKEN']
    branch = app.config['GITLAB_BRANCH']
    
    logger.info(f"=== GitLab Pipeline Trigger ===")
    logger.info(f"GitLab URL: {gitlab_url}")
    logger.info(f"Project ID: {project_id}")
    logger.info(f"Branch: {branch}")
    logger.info(f"Token: {token[:15]}..." if token and len(token) > 15 else f"Token: {token}")
    
    if not all([gitlab_url, project_id, token]):
        logger.error("GitLab configuration missing!")
        return {'success': False, 'error': 'GitLab configuration missing'}
    
    # Using pipeline trigger with variables
    trigger_url = f"{gitlab_url}/api/v4/projects/{project_id}/trigger/pipeline"
    
    logger.info(f"Trigger URL: {trigger_url}")
    
    # Prepare domains as newline-separated string
    domains_content = '\n'.join(domains)
    
    # Create pipeline with file variables
    data = {
        'token': token,
        'ref': branch,
        'variables[CERT_CONTENT]': cert_content,
        'variables[KEY_CONTENT]': key_content,
        'variables[DOMAINS_CONTENT]': domains_content,
        'variables[TRIGGERED_BY]': 'ssl-automation-api',
        'variables[TRIGGER_TIME]': datetime.now(timezone.utc).isoformat(),
    }
    
    logger.info(f"Request data keys: {list(data.keys())}")
    
    try:
        logger.info(f"Sending POST request to {trigger_url}")
        response = requests.post(trigger_url, data=data, timeout=30)
        
        logger.info(f"Response status code: {response.status_code}")
        logger.info(f"Response headers: {dict(response.headers)}")
        logger.info(f"Response body: {response.text[:1000]}")
        
        if response.status_code in [200, 201]:
            result = response.json()
            logger.info(f"Pipeline triggered successfully! ID: {result.get('id')}")
            return {
                'success': True,
                'pipeline_id': result.get('id'),
                'pipeline_url': result.get('web_url'),
                'status': result.get('status'),
            }
        else:
            logger.error(f"GitLab API error: {response.status_code}")
            logger.error(f"Response: {response.text}")
            return {
                'success': False,
                'error': f'GitLab API error: {response.status_code}',
                'details': response.text
            }
    except requests.exceptions.RequestException as e:
        logger.error(f"Request exception: {e}")
        return {'success': False, 'error': f'Request failed: {e}'}


def commit_and_trigger(cert_content: str, key_content: str, domains: list) -> dict:
    """Commit files to GitLab and trigger pipeline"""
    import requests
    
    gitlab_url = app.config['GITLAB_URL']
    project_id = app.config['GITLAB_PROJECT_ID']
    token = app.config['GITLAB_TOKEN']
    branch = app.config['GITLAB_BRANCH']
    
    if not all([gitlab_url, project_id, token]):
        return {'success': False, 'error': 'GitLab configuration missing'}
    
    headers = {'PRIVATE-TOKEN': token, 'Content-Type': 'application/json'}
    
    # Prepare commit actions
    import base64
    actions = [
        {
            'action': 'update',
            'file_path': 'certs/certificate.crt',
            'content': cert_content,
        },
        {
            'action': 'update',
            'file_path': 'certs/certificate.key',
            'content': key_content,
        },
        {
            'action': 'update',
            'file_path': 'certs/domains.txt',
            'content': '\n'.join(domains),
        },
    ]
    
    commit_data = {
        'branch': branch,
        'commit_message': f'[SSL Automation] Update certificates - {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")}',
        'actions': actions,
    }
    
    try:
        # Create commit
        commit_url = f"{gitlab_url}/api/v4/projects/{project_id}/repository/commits"
        response = requests.post(commit_url, headers=headers, json=commit_data, timeout=30)
        
        if response.status_code in [200, 201]:
            result = response.json()
            return {
                'success': True,
                'commit_id': result.get('id'),
                'commit_url': result.get('web_url'),
                'message': 'Files committed, pipeline will trigger automatically',
            }
        elif response.status_code == 400 and 'already exists' in response.text.lower():
            # Files might need 'update' instead of 'create'
            return {'success': False, 'error': 'Commit failed - files may not exist yet', 'details': response.text}
        else:
            return {'success': False, 'error': f'GitLab API error: {response.status_code}', 'details': response.text}
            
    except requests.exceptions.RequestException as e:
        return {'success': False, 'error': f'Request failed: {e}'}


# API Routes

@app.route('/')
def index():
    """Render main upload form"""
    return render_template('index.html')


@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({'status': 'ok', 'time': datetime.now(timezone.utc).isoformat()})


@app.route('/api/validate', methods=['POST'])
@require_api_key
def validate():
    """Validate certificate and key without deploying"""
    logger.info("=== Validate Request ===")
    
    if 'certificate' not in request.files:
        return jsonify({'error': 'Certificate file required'}), 400
    if 'key' not in request.files:
        return jsonify({'error': 'Key file required'}), 400
    
    cert_file = request.files['certificate']
    key_file = request.files['key']
    
    cert_data = cert_file.read()
    key_data = key_file.read()
    
    logger.info(f"Certificate size: {len(cert_data)} bytes")
    logger.info(f"Key size: {len(key_data)} bytes")
    
    # Validate certificate
    cert_result = validate_certificate(cert_data)
    if not cert_result['valid']:
        logger.error(f"Certificate validation failed: {cert_result['error']}")
        return jsonify({'valid': False, 'error': cert_result['error']}), 400
    
    # Validate key
    key_result = validate_private_key(key_data)
    if not key_result['valid']:
        logger.error(f"Key validation failed: {key_result['error']}")
        return jsonify({'valid': False, 'error': key_result['error']}), 400
    
    # Verify pair
    if not verify_key_pair(cert_data, key_data):
        logger.error("Certificate and key do not match")
        return jsonify({'valid': False, 'error': 'Certificate and key do not match'}), 400
    
    # Parse domains if provided
    domains_input = request.form.get('domains', '')
    domains = []
    domain_errors = []
    if domains_input:
        domains, domain_errors = parse_domains(domains_input)
    
    logger.info(f"Validation successful. Domains: {domains}")
    
    return jsonify({
        'valid': True,
        'certificate': cert_result,
        'key': key_result,
        'domains_parsed': domains,
        'domains_count': len(domains),
        'domain_errors': domain_errors,
    })


@app.route('/api/deploy', methods=['POST'])
@require_api_key
def deploy():
    """Upload certificates and trigger deployment pipeline"""
    logger.info("=== Deploy Request ===")
    
    # Check required files
    if 'certificate' not in request.files:
        return jsonify({'error': 'Certificate file required'}), 400
    if 'key' not in request.files:
        return jsonify({'error': 'Key file required'}), 400
    
    cert_file = request.files['certificate']
    key_file = request.files['key']
    domains_input = request.form.get('domains', '')
    
    # Read file contents
    cert_data = cert_file.read()
    key_data = key_file.read()
    
    logger.info(f"Certificate size: {len(cert_data)} bytes")
    logger.info(f"Key size: {len(key_data)} bytes")
    logger.info(f"Domains input: {domains_input[:100]}...")
    
    # Validate certificate
    cert_result = validate_certificate(cert_data)
    if not cert_result['valid']:
        logger.error(f"Certificate validation failed: {cert_result['error']}")
        return jsonify({'success': False, 'error': cert_result['error']}), 400
    
    if cert_result['expired']:
        logger.error("Certificate is expired")
        return jsonify({'success': False, 'error': 'Certificate is expired'}), 400
    
    # Validate key
    key_result = validate_private_key(key_data)
    if not key_result['valid']:
        logger.error(f"Key validation failed: {key_result['error']}")
        return jsonify({'success': False, 'error': key_result['error']}), 400
    
    # Verify pair
    if not verify_key_pair(cert_data, key_data):
        logger.error("Certificate and key do not match")
        return jsonify({'success': False, 'error': 'Certificate and key do not match'}), 400
    
    # Parse and validate domains
    domains, domain_errors = parse_domains(domains_input)
    
    if domain_errors:
        logger.error(f"Invalid domains: {domain_errors}")
        return jsonify({
            'success': False, 
            'error': 'Invalid domains detected',
            'domain_errors': domain_errors
        }), 400
    
    if not domains:
        logger.error("No valid domains provided")
        return jsonify({'success': False, 'error': 'At least one valid domain is required'}), 400
    
    logger.info(f"Valid domains: {domains}")
    
    # Trigger deployment
    deploy_method = request.form.get('method', 'trigger')  # 'commit' or 'trigger'
    
    logger.info(f"Deploy method: {deploy_method}")
    
    if deploy_method == 'commit':
        result = commit_and_trigger(
            cert_data.decode('utf-8'),
            key_data.decode('utf-8'),
            domains
        )
    else:
        result = trigger_gitlab_pipeline(
            cert_data.decode('utf-8'),
            key_data.decode('utf-8'),
            domains
        )
    
    if result['success']:
        logger.info(f"Deployment triggered successfully: {result}")
        return jsonify({
            'success': True,
            'message': 'Deployment triggered successfully',
            'certificate': {
                'subject': cert_result['subject'],
                'expires': cert_result['not_after'],
                'days_remaining': cert_result['days_remaining'],
            },
            'domains': domains,
            'pipeline': result,
        })
    else:
        logger.error(f"Deployment failed: {result}")
        return jsonify({'success': False, 'error': result['error']}), 500


@app.route('/api/status/<pipeline_id>')
@require_api_key
def pipeline_status(pipeline_id):
    """Get pipeline status from GitLab"""
    import requests
    
    gitlab_url = app.config['GITLAB_URL']
    project_id = app.config['GITLAB_PROJECT_ID']
    token = app.config['GITLAB_TOKEN']
    
    if not all([gitlab_url, project_id, token]):
        return jsonify({'error': 'GitLab configuration missing'}), 500
    
    headers = {'PRIVATE-TOKEN': token}
    url = f"{gitlab_url}/api/v4/projects/{project_id}/pipelines/{pipeline_id}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return jsonify({
                'id': data.get('id'),
                'status': data.get('status'),
                'web_url': data.get('web_url'),
                'created_at': data.get('created_at'),
                'updated_at': data.get('updated_at'),
            })
        else:
            return jsonify({'error': 'Pipeline not found'}), 404
    except requests.exceptions.RequestException as e:
        return jsonify({'error': str(e)}), 500


# Error Handlers

@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 16MB'}), 413


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


# Run Application

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    logger.info(f"Starting SSL Automation API on port {port}")
    logger.info(f"GitLab URL: {app.config['GITLAB_URL']}")
    logger.info(f"GitLab Project ID: {app.config['GITLAB_PROJECT_ID']}")
    app.run(host='0.0.0.0', port=port, debug=debug)
