"""
ThreatLens TI — Multi-Source Threat Intelligence Aggregation Platform
Flask backend that proxies IOC lookups to VirusTotal, AbuseIPDB, IPInfo, OTX AlienVault,
EmailRep.io, Hunter.io, and URLScan.io.
"""

import os
import re
import io
import csv
import time
import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import wraps

import requests
from flask import Flask, render_template, request, jsonify, Response
from flask_caching import Cache
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

# --- Logging ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)

# --- Extensions ---
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache', 'CACHE_DEFAULT_TIMEOUT': 300})
limiter = Limiter(get_remote_address, app=app, default_limits=['60 per minute'])
CORS(app, resources={r'/api/*': {'origins': '*'}})

# --- API Keys ---
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
ABUSE_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
IPINFO_API_KEY = os.getenv('IPINFO_API_KEY', '')
OTX_API_KEY = os.getenv('OTX_API_KEY', '')
HUNTER_API_KEY = os.getenv('HUNTER_API_KEY', '')
URLSCAN_API_KEY = os.getenv('URLSCAN_API_KEY', '')

# --- Constants ---
REQUEST_TIMEOUT = 12  # seconds per API call
MAX_WORKERS = 8
MAX_QUERY_LENGTH = 256

# --- IOC Type Detection ---
IPV6_PATTERN = re.compile(
    r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|'
    r'^([0-9a-fA-F]{1,4}:){1,7}:$|'
    r'^([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}$|'
    r'^([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}$|'
    r'^([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}$|'
    r'^([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}$|'
    r'^([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}$|'
    r'^[0-9a-fA-F]{1,4}:(:[0-9a-fA-F]{1,4}){1,6}$|'
    r'^:((:[0-9a-fA-F]{1,4}){1,7}|:)$|'
    r'^::$'
)

def detect_ioc_type(query):
    """Auto-detect the type of Indicator of Compromise."""
    query = query.strip()

    # IPv4 address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', query):
        octets = query.split('.')
        if all(0 <= int(o) <= 255 for o in octets):
            return 'ip'

    # IPv6 address
    if IPV6_PATTERN.match(query):
        return 'ip'

    # File hash (MD5=32, SHA1=40, SHA256=64)
    if re.match(r'^[a-fA-F0-9]{32}$', query):
        return 'hash'
    if re.match(r'^[a-fA-F0-9]{40}$', query):
        return 'hash'
    if re.match(r'^[a-fA-F0-9]{64}$', query):
        return 'hash'

    # Email address
    if re.match(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$', query):
        return 'email'

    # Domain (contains dots, not an IP, no spaces)
    if re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', query):
        return 'domain'

    return 'unknown'


# --- API Query Functions ---
# Each function returns a dict with: source, success, data, error

def query_virustotal(ioc, ioc_type):
    """Query VirusTotal API v3."""
    if not VT_API_KEY:
        return {'source': 'virustotal', 'success': False, 'error': 'No API key configured', 'data': None}

    headers = {'x-apikey': VT_API_KEY}
    base_url = 'https://www.virustotal.com/api/v3'

    try:
        if ioc_type == 'ip':
            url = f'{base_url}/ip_addresses/{ioc}'
        elif ioc_type == 'domain':
            url = f'{base_url}/domains/{ioc}'
        elif ioc_type == 'hash':
            url = f'{base_url}/files/{ioc}'
        elif ioc_type == 'email':
            return {'source': 'virustotal', 'success': True, 'error': None, 'data': {'not_applicable': True, 'message': 'VirusTotal does not support email lookups'}}
        else:
            return {'source': 'virustotal', 'success': False, 'error': 'Unsupported IOC type', 'data': None}

        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 429:
            return {'source': 'virustotal', 'success': False, 'error': 'Rate limit exceeded (4 req/min on free tier)', 'data': None}
        if resp.status_code == 404:
            return {'source': 'virustotal', 'success': True, 'error': None, 'data': {'found': False, 'message': 'IOC not found in VirusTotal database'}}
        if resp.status_code != 200:
            return {'source': 'virustotal', 'success': False, 'error': f'HTTP {resp.status_code}: {resp.text[:200]}', 'data': None}

        raw = resp.json().get('data', {})
        attrs = raw.get('attributes', {})

        result = {
            'found': True,
            'ioc_type': ioc_type,
        }

        if ioc_type == 'ip':
            stats = attrs.get('last_analysis_stats', {})
            result['malicious'] = stats.get('malicious', 0)
            result['suspicious'] = stats.get('suspicious', 0)
            result['harmless'] = stats.get('harmless', 0)
            result['undetected'] = stats.get('undetected', 0)
            result['total_engines'] = sum(stats.values()) if stats else 0
            result['reputation'] = attrs.get('reputation', 'N/A')
            result['country'] = attrs.get('country', 'Unknown')
            result['as_owner'] = attrs.get('as_owner', 'Unknown')
            result['network'] = attrs.get('network', 'Unknown')
            result['last_analysis_date'] = attrs.get('last_analysis_date', None)
            # Compute score: malicious detections / total engines * 100
            if result['total_engines'] > 0:
                result['score'] = round((result['malicious'] + result['suspicious']) / result['total_engines'] * 100, 1)
            else:
                result['score'] = 0

        elif ioc_type == 'domain':
            stats = attrs.get('last_analysis_stats', {})
            result['malicious'] = stats.get('malicious', 0)
            result['suspicious'] = stats.get('suspicious', 0)
            result['harmless'] = stats.get('harmless', 0)
            result['undetected'] = stats.get('undetected', 0)
            result['total_engines'] = sum(stats.values()) if stats else 0
            result['reputation'] = attrs.get('reputation', 'N/A')
            result['registrar'] = attrs.get('registrar', 'Unknown')
            result['creation_date'] = attrs.get('creation_date', None)
            result['last_analysis_date'] = attrs.get('last_analysis_date', None)
            result['categories'] = attrs.get('categories', {})
            if result['total_engines'] > 0:
                result['score'] = round((result['malicious'] + result['suspicious']) / result['total_engines'] * 100, 1)
            else:
                result['score'] = 0

        elif ioc_type == 'hash':
            stats = attrs.get('last_analysis_stats', {})
            result['malicious'] = stats.get('malicious', 0)
            result['suspicious'] = stats.get('suspicious', 0)
            result['harmless'] = stats.get('harmless', 0)
            result['undetected'] = stats.get('undetected', 0)
            result['total_engines'] = sum(stats.values()) if stats else 0
            result['reputation'] = attrs.get('reputation', 'N/A')
            result['file_name'] = attrs.get('meaningful_name', attrs.get('names', ['Unknown'])[0] if attrs.get('names') else 'Unknown')
            result['file_type'] = attrs.get('type_description', 'Unknown')
            result['file_size'] = attrs.get('size', 0)
            result['sha256'] = attrs.get('sha256', 'N/A')
            result['md5'] = attrs.get('md5', 'N/A')
            result['sha1'] = attrs.get('sha1', 'N/A')
            result['tags'] = attrs.get('tags', [])
            result['last_analysis_date'] = attrs.get('last_analysis_date', None)
            if result['total_engines'] > 0:
                result['score'] = round((result['malicious'] + result['suspicious']) / result['total_engines'] * 100, 1)
            else:
                result['score'] = 0

        return {'source': 'virustotal', 'success': True, 'error': None, 'data': result}

    except requests.exceptions.Timeout:
        return {'source': 'virustotal', 'success': False, 'error': 'Request timed out', 'data': None}
    except Exception as e:
        return {'source': 'virustotal', 'success': False, 'error': str(e)[:200], 'data': None}


def query_abuseipdb(ioc, ioc_type):
    """Query AbuseIPDB API v2. Only supports IP addresses."""
    if ioc_type not in ('ip',):
        return {'source': 'abuseipdb', 'success': True, 'error': None, 'data': {'not_applicable': True, 'message': 'AbuseIPDB only supports IP address lookups'}}

    if not ABUSE_API_KEY:
        return {'source': 'abuseipdb', 'success': False, 'error': 'No API key configured', 'data': None}

    headers = {
        'Key': ABUSE_API_KEY,
        'Accept': 'application/json'
    }
    params = {
        'ipAddress': ioc,
        'maxAgeInDays': 90,
        'verbose': ''
    }

    try:
        resp = requests.get('https://api.abuseipdb.com/api/v2/check',
                            headers=headers, params=params, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 429:
            return {'source': 'abuseipdb', 'success': False, 'error': 'Rate limit exceeded', 'data': None}
        if resp.status_code != 200:
            return {'source': 'abuseipdb', 'success': False, 'error': f'HTTP {resp.status_code}', 'data': None}

        raw = resp.json().get('data', {})

        # Extract recent reports/comments and category tags
        reports = raw.get('reports', [])
        comments = []
        categories_set = set()

        # AbuseIPDB Category Mappings
        ABUSE_CATEGORIES = {
            1: 'DNS Compromise', 2: 'DNS Poisoning', 3: 'Fraud Webmail', 4: 'DDoS Attack',
            5: 'FTP Brute-Force', 6: 'Ping of Death', 7: 'Phishing', 8: 'Fraud VoIP',
            9: 'Open Proxy', 10: 'Web Spam', 11: 'Email Spam', 12: 'Blog Spam',
            13: 'VPN IP', 14: 'Port Scan', 15: 'Hacking', 16: 'SQL Injection',
            17: 'Spoofing', 18: 'SSH Brute-Force', 19: 'Bad Web Bot', 20: 'Exploited Host',
            21: 'Web App Attack', 22: 'SSH Abuse', 23: 'IoT Targeted'
        }

        for r_item in reports:
            comment_text = r_item.get('comment', '').strip()
            if comment_text and comment_text not in comments:
                comments.append(comment_text)

            # Map category IDs to string names
            cats = r_item.get('categories', [])
            for c_id in cats:
                cat_name = ABUSE_CATEGORIES.get(c_id)
                if cat_name:
                    categories_set.add(cat_name)

        result = {
            'found': True,
            'abuse_confidence_score': raw.get('abuseConfidenceScore', 0),
            'total_reports': raw.get('totalReports', 0),
            'num_distinct_users': raw.get('numDistinctUsers', 0),
            'country_code': raw.get('countryCode', 'Unknown'),
            'isp': raw.get('isp', 'Unknown'),
            'usage_type': raw.get('usageType', 'Unknown'),
            'domain': raw.get('domain', 'Unknown'),
            'is_tor': raw.get('isTor', False),
            'is_whitelisted': raw.get('isWhitelisted', False),
            'last_reported_at': raw.get('lastReportedAt', None),
            'comments': comments,  # Return all unique comments
            'tags': sorted(list(categories_set)),  # Unique category tags
            'score': raw.get('abuseConfidenceScore', 0)
        }

        return {'source': 'abuseipdb', 'success': True, 'error': None, 'data': result}

    except requests.exceptions.Timeout:
        return {'source': 'abuseipdb', 'success': False, 'error': 'Request timed out', 'data': None}
    except Exception as e:
        return {'source': 'abuseipdb', 'success': False, 'error': str(e)[:200], 'data': None}


def query_ipinfo(ioc, ioc_type):
    """Query IPInfo API. Only supports IP addresses."""
    if ioc_type != 'ip':
        return {'source': 'ipinfo', 'success': True, 'error': None, 'data': {'not_applicable': True, 'message': 'IPInfo only supports IP address lookups'}}

    if not IPINFO_API_KEY:
        return {'source': 'ipinfo', 'success': False, 'error': 'No API key configured', 'data': None}

    try:
        # Fetch standard info
        resp = requests.get(f'https://ipinfo.io/{ioc}',
                            params={'token': IPINFO_API_KEY},
                            timeout=REQUEST_TIMEOUT)

        if resp.status_code != 200:
            return {'source': 'ipinfo', 'success': False, 'error': f'HTTP {resp.status_code}', 'data': None}

        raw = resp.json()

        # Try fetching privacy details
        privacy_data = {}
        try:
            p_resp = requests.get(f'https://ipinfo.io/{ioc}/privacy',
                                  params={'token': IPINFO_API_KEY},
                                  timeout=REQUEST_TIMEOUT)
            if p_resp.status_code == 200:
                privacy_data = p_resp.json()
        except Exception:
            pass

        result = {
            'found': True,
            'ip': raw.get('ip', ioc),
            'hostname': raw.get('hostname', 'N/A'),
            'city': raw.get('city', 'Unknown'),
            'region': raw.get('region', 'Unknown'),
            'country': raw.get('country', 'Unknown'),
            'loc': raw.get('loc', 'N/A'),
            'org': raw.get('org', 'Unknown'),
            'postal': raw.get('postal', 'N/A'),
            'timezone': raw.get('timezone', 'Unknown'),
            'is_bogon': raw.get('bogon', False),
            'anycast': raw.get('anycast', False),
            'privacy': {
                'vpn': privacy_data.get('vpn', False),
                'proxy': privacy_data.get('proxy', False),
                'tor': privacy_data.get('tor', False),
                'relay': privacy_data.get('relay', False),
                'hosting': privacy_data.get('hosting', False),
                'service': privacy_data.get('service', '')
            },
            'score': 0
        }

        # If VPN, Tor, or Proxy is active, adjust score/risk representation for this enrichment
        # (Though IPInfo remains 0 in composite score calculation, standard indicators can be flagged)
        return {'source': 'ipinfo', 'success': True, 'error': None, 'data': result}

    except requests.exceptions.Timeout:
        return {'source': 'ipinfo', 'success': False, 'error': 'Request timed out', 'data': None}
    except Exception as e:
        return {'source': 'ipinfo', 'success': False, 'error': str(e)[:200], 'data': None}


def query_otx_alienvault(ioc, ioc_type):
    """Query OTX AlienVault API v1."""
    if not OTX_API_KEY:
        return {'source': 'otx', 'success': False, 'error': 'No API key configured', 'data': None}

    headers = {'X-OTX-API-KEY': OTX_API_KEY}
    base_url = 'https://otx.alienvault.com/api/v1/indicators'

    try:
        if ioc_type == 'ip':
            url = f'{base_url}/IPv4/{ioc}/general'
        elif ioc_type == 'domain':
            url = f'{base_url}/domain/{ioc}/general'
        elif ioc_type == 'hash':
            url = f'{base_url}/file/{ioc}/general'
        else:
            return {'source': 'otx', 'success': False, 'error': 'Unsupported IOC type', 'data': None}

        resp = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)

        if resp.status_code == 404:
            return {'source': 'otx', 'success': True, 'error': None, 'data': {'found': False, 'message': 'IOC not found in OTX database'}}
        if resp.status_code != 200:
            return {'source': 'otx', 'success': False, 'error': f'HTTP {resp.status_code}', 'data': None}

        raw = resp.json()

        pulse_count = raw.get('pulse_info', {}).get('count', 0)
        pulses = raw.get('pulse_info', {}).get('pulses', [])

        # Extract tags and malware families from pulses
        tags = set()
        malware_families = set()
        for pulse in pulses[:10]:  # Limit to first 10 pulses
            for tag in pulse.get('tags', []):
                tags.add(tag)
            for mf in pulse.get('malware_families', []):
                if isinstance(mf, dict):
                    malware_families.add(mf.get('display_name', ''))
                elif isinstance(mf, str):
                    malware_families.add(mf)

        # Calculate a simple score based on pulse count
        if pulse_count == 0:
            score = 0
        elif pulse_count <= 2:
            score = 25
        elif pulse_count <= 10:
            score = 50
        elif pulse_count <= 50:
            score = 75
        else:
            score = 95

        result = {
            'found': True,
            'pulse_count': pulse_count,
            'tags': list(tags)[:15],
            'malware_families': list(malware_families)[:10],
            'country': raw.get('country_name', 'Unknown'),
            'asn': raw.get('asn', 'N/A'),
            'reputation': raw.get('reputation', 0),
            'indicator': raw.get('indicator', ioc),
            'type_title': raw.get('type_title', ioc_type),
            'score': score
        }

        return {'source': 'otx', 'success': True, 'error': None, 'data': result}

    except requests.exceptions.Timeout:
        return {'source': 'otx', 'success': False, 'error': 'Request timed out', 'data': None}
    except Exception as e:
        return {'source': 'otx', 'success': False, 'error': str(e)[:200], 'data': None}


# --- Email Investigation Functions ---

def query_emailrep(ioc, ioc_type):
    """Query EmailRep.io API. Free, no API key needed. Email only."""
    if ioc_type != 'email':
        return {'source': 'emailrep', 'success': True, 'error': None, 'data': {'not_applicable': True, 'message': 'EmailRep only supports email lookups'}}

    try:
        resp = requests.get(f'https://emailrep.io/{ioc}',
                            headers={'User-Agent': 'ThreatLens-TI/1.0'},
                            timeout=REQUEST_TIMEOUT)

        if resp.status_code == 429:
            return {'source': 'emailrep', 'success': False, 'error': 'Rate limit exceeded', 'data': None}
        if resp.status_code != 200:
            return {'source': 'emailrep', 'success': False, 'error': f'HTTP {resp.status_code}', 'data': None}

        raw = resp.json()
        reputation = raw.get('reputation', 'none')
        suspicious = raw.get('suspicious', False)
        details = raw.get('details', {})

        # Score mapping
        rep_scores = {'high': 0, 'medium': 30, 'low': 65, 'none': 85}
        score = rep_scores.get(reputation, 50)
        if suspicious:
            score = max(score, 75)

        result = {
            'found': True,
            'email': raw.get('email', ioc),
            'reputation': reputation,
            'suspicious': suspicious,
            'references': raw.get('references', 0),
            'blacklisted': details.get('blacklisted', False),
            'malicious_activity': details.get('malicious_activity', False),
            'credential_leaked': details.get('credentials_leaked', False),
            'data_breach': details.get('data_breach', False),
            'spam': details.get('spam', False),
            'free_provider': details.get('free_provider', False),
            'disposable': details.get('disposable', False),
            'deliverable': details.get('deliverable', False),
            'accept_all': details.get('accept_all', False),
            'valid_mx': details.get('valid_mx', False),
            'spoofable': details.get('spoofable', False),
            'spf_strict': details.get('spf_strict', False),
            'dmarc_enforced': details.get('dmarc_enforced', False),
            'domain_reputation': details.get('domain_reputation', 'unknown'),
            'profiles': details.get('profiles', []),
            'days_since_creation': details.get('days_since_domain_creation', None),
            'last_seen': details.get('last_seen', 'never'),
            'score': score
        }

        return {'source': 'emailrep', 'success': True, 'error': None, 'data': result}

    except requests.exceptions.Timeout:
        return {'source': 'emailrep', 'success': False, 'error': 'Request timed out', 'data': None}
    except Exception as e:
        return {'source': 'emailrep', 'success': False, 'error': str(e)[:200], 'data': None}


def query_hunterio(ioc, ioc_type):
    """Query Hunter.io Email Verifier API. Email only."""
    if ioc_type != 'email':
        return {'source': 'hunterio', 'success': True, 'error': None, 'data': {'not_applicable': True, 'message': 'Hunter.io only supports email lookups'}}

    if not HUNTER_API_KEY:
        return {'source': 'hunterio', 'success': False, 'error': 'No API key configured', 'data': None}

    try:
        resp = requests.get('https://api.hunter.io/v2/email-verifier',
                            params={'email': ioc, 'api_key': HUNTER_API_KEY},
                            timeout=REQUEST_TIMEOUT)

        if resp.status_code == 429:
            return {'source': 'hunterio', 'success': False, 'error': 'Rate limit exceeded (25 req/month free)', 'data': None}
        if resp.status_code != 200:
            return {'source': 'hunterio', 'success': False, 'error': f'HTTP {resp.status_code}', 'data': None}

        raw = resp.json().get('data', {})

        status = raw.get('status', 'unknown')
        result_val = raw.get('result', 'unknown')
        score_val = raw.get('score', 0)

        # risky or undeliverable = higher threat
        threat_score = 0
        if result_val == 'undeliverable':
            threat_score = 60
        elif result_val == 'risky':
            threat_score = 40
        elif status == 'disposable':
            threat_score = 70

        result = {
            'found': True,
            'email': raw.get('email', ioc),
            'result': result_val,
            'hunter_score': score_val,
            'status': status,
            'disposable': raw.get('disposable', False),
            'webmail': raw.get('webmail', False),
            'mx_records': raw.get('mx_records', False),
            'smtp_server': raw.get('smtp_server', False),
            'smtp_check': raw.get('smtp_check', False),
            'accept_all': raw.get('accept_all', False),
            'block': raw.get('block', False),
            'sources': raw.get('sources', []),
            'score': threat_score
        }

        return {'source': 'hunterio', 'success': True, 'error': None, 'data': result}

    except requests.exceptions.Timeout:
        return {'source': 'hunterio', 'success': False, 'error': 'Request timed out', 'data': None}
    except Exception as e:
        return {'source': 'hunterio', 'success': False, 'error': str(e)[:200], 'data': None}




def query_urlscan(ioc, ioc_type):
    """Query URLScan.io search API. Supports domains and IPs."""
    if ioc_type not in ('domain', 'ip'):
        return {'source': 'urlscan', 'success': True, 'error': None, 'data': {'not_applicable': True, 'message': 'URLScan only supports domain and IP lookups'}}

    headers = {}
    if URLSCAN_API_KEY:
        headers['API-Key'] = URLSCAN_API_KEY

    try:
        if ioc_type == 'domain':
            query_str = f'page.domain:{ioc}'
        else:
            query_str = f'page.ip:{ioc}'

        resp = requests.get(f'https://urlscan.io/api/v1/search/?q={query_str}',
                            headers=headers,
                            timeout=REQUEST_TIMEOUT)

        if resp.status_code == 429:
            return {'source': 'urlscan', 'success': False, 'error': 'Rate limit exceeded', 'data': None}
        if resp.status_code != 200:
            return {'source': 'urlscan', 'success': False, 'error': f'HTTP {resp.status_code}', 'data': None}

        data = resp.json()
        results = data.get('results', [])
        if not results:
            return {'source': 'urlscan', 'success': True, 'error': None, 'data': {'found': False, 'message': 'No recent scans found for this IOC in URLScan database.'}}

        latest = results[0]
        page = latest.get('page', {})
        stats = latest.get('stats', {})
        task = latest.get('task', {})
        verdicts = latest.get('verdicts', {}).get('overall', {})

        malicious = verdicts.get('malicious', False)
        score = verdicts.get('score', 0)

        threat_score = score
        if malicious:
            threat_score = max(threat_score, 85)

        result = {
            'found': True,
            'uuid': latest.get('_id'),
            'page_url': page.get('url', 'N/A'),
            'page_title': page.get('title', 'N/A'),
            'page_ip': page.get('ip', 'N/A'),
            'page_country': page.get('country', 'N/A'),
            'server': page.get('server', 'N/A'),
            'asn_name': page.get('asnname', 'N/A'),
            'asn': page.get('asn', 'N/A'),
            'requests_count': stats.get('requests', 0),
            'unique_ips': stats.get('uniqIPs', 0),
            'unique_countries': stats.get('uniqCountries', 0),
            'scan_time': task.get('time', 'N/A'),
            'malicious': malicious,
            'score': threat_score,
            'result_url': f"https://urlscan.io/result/{latest.get('_id')}/",
            'screenshot_url': f"https://urlscan.io/screenshots/{latest.get('_id')}.png"
        }
        return {'source': 'urlscan', 'success': True, 'error': None, 'data': result}

    except requests.exceptions.Timeout:
        return {'source': 'urlscan', 'success': False, 'error': 'Request timed out', 'data': None}
    except Exception as e:
        return {'source': 'urlscan', 'success': False, 'error': str(e)[:200], 'data': None}


def query_domain_checker(ioc, ioc_type):
    """Query free RDAP WHOIS bootstrap for domain registration details."""
    if ioc_type != 'domain':
        return {'source': 'domain_checker', 'success': True, 'error': None, 'data': {'not_applicable': True, 'message': 'Domain Checker only supports domain lookups'}}

    try:
        resp = requests.get(f'https://rdap.org/domain/{ioc}',
                            headers={'Accept': 'application/json'},
                            allow_redirects=True,
                            timeout=REQUEST_TIMEOUT)

        if resp.status_code == 404:
            return {'source': 'domain_checker', 'success': True, 'error': None, 'data': {'found': False, 'message': 'Domain registration record not found in RDAP database.'}}
        if resp.status_code != 200:
            return {'source': 'domain_checker', 'success': False, 'error': f'HTTP {resp.status_code}', 'data': None}

        data = resp.json()

        created_date = None
        expires_date = None
        changed_date = None
        for e in data.get('events', []):
            action = e.get('eventAction')
            date_val = e.get('eventDate')
            if action == 'registration':
                created_date = date_val
            elif action == 'expiration':
                expires_date = date_val
            elif action == 'last changed':
                changed_date = date_val

        registrar = 'Unknown'
        for ent in data.get('entities', []):
            roles = ent.get('roles', [])
            if 'registrar' in roles:
                vcard = ent.get('vcardArray', [])
                if len(vcard) > 1:
                    for item in vcard[1]:
                        if item[0] == 'fn':
                            registrar = item[3]
                            break

        nameservers = [ns.get('ldhName') for ns in data.get('nameservers', []) if ns.get('ldhName')]

        domain_age_days = None
        threat_score = 0
        risk_flags = []

        if created_date:
            try:
                clean_date = created_date.split('T')[0]
                created_dt = datetime.strptime(clean_date, '%Y-%m-%d')
                now_dt = datetime.utcnow()
                domain_age_days = (now_dt - created_dt).days

                if domain_age_days < 30:
                    threat_score = 80
                    risk_flags.append('Newly Registered Domain (< 30 days old)')
                elif domain_age_days < 180:
                    threat_score = 30
                    risk_flags.append('Young Domain (< 6 months old)')
            except Exception:
                pass

        result = {
            'found': True,
            'creation_date': created_date or 'N/A',
            'expiration_date': expires_date or 'N/A',
            'last_changed': changed_date or 'N/A',
            'registrar': registrar,
            'nameservers': nameservers[:5],
            'status': data.get('status', []),
            'age_days': domain_age_days,
            'risk_flags': risk_flags,
            'score': threat_score
        }
        return {'source': 'domain_checker', 'success': True, 'error': None, 'data': result}

    except requests.exceptions.Timeout:
        return {'source': 'domain_checker', 'success': False, 'error': 'Request timed out', 'data': None}
    except Exception as e:
        return {'source': 'domain_checker', 'success': False, 'error': str(e)[:200], 'data': None}


# --- DNS & Passive DNS History ---
def query_dns_history(ioc, ioc_type):
    """Query Active DNS (via HackerTarget API) and Passive DNS (via Mnemonic API). Only for domains."""
    if ioc_type != 'domain':
        return {'source': 'dns_history', 'success': True, 'error': None, 'data': {'not_applicable': True}}

    active_records = []
    passive_records = []

    # 1. Fetch Active DNS (HackerTarget)
    try:
        resp = requests.get(f'https://api.hackertarget.com/dnslookup/?q={ioc}', timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200 and resp.text:
            lines = resp.text.split('\n')
            for line in lines:
                if ' : ' in line:
                    parts = line.split(' : ', 1)
                    dtype = parts[0].strip()
                    dvalue = parts[1].strip()
                    active_records.append({
                        'type': dtype,
                        'value': dvalue
                    })
    except Exception as e:
        logger.warning(f"Error querying HackerTarget Active DNS for {ioc}: {e}")

    # 2. Fetch Passive DNS (Mnemonic)
    try:
        resp = requests.get(f'https://api.mnemonic.no/pdns/v3/{ioc}?limit=15', timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            raw_data = resp.json().get('data', [])
            for item in raw_data:
                first_seen = item.get('firstSeenTimestamp')
                last_seen = item.get('lastSeenTimestamp')
                
                # Convert epoch timestamp to readable UTC date
                first_seen_str = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(first_seen / 1000.0)) if first_seen else 'N/A'
                last_seen_str = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(last_seen / 1000.0)) if last_seen else 'N/A'
                
                passive_records.append({
                    'answer': item.get('answer', 'Unknown'),
                    'rrtype': item.get('rrtype', 'A').upper(),
                    'first_seen': first_seen_str,
                    'last_seen': last_seen_str,
                    'count': item.get('times', 1)
                })
    except Exception as e:
        logger.warning(f"Error querying Mnemonic Passive DNS for {ioc}: {e}")

    return {
        'source': 'dns_history',
        'success': True,
        'error': None,
        'data': {
            'found': True,
            'active': active_records,
            'passive': passive_records,
            'score': 0
        }
    }


# --- Unified Threat Scoring ---
def calculate_unified_score(results):
    """
    Calculate a weighted composite threat score from all sources.
    Weights vary by IOC type.
    """
    weights = {
        'virustotal': 0.35,
        'abuseipdb': 0.25,
        'otx': 0.20,
        'ipinfo': 0.05,
        'emailrep': 0.35,
        'hunterio': 0.15,
        'urlscan': 0.20,
        'domain_checker': 0.15,
        'dns_history': 0.0
    }

    total_weight = 0
    weighted_score = 0

    for r in results:
        source = r.get('source')
        if not r.get('success') or not r.get('data'):
            continue
        data = r['data']
        if data.get('not_applicable') or not data.get('found', True):
            continue

        score = data.get('score', 0)
        w = weights.get(source, 0.1)
        weighted_score += score * w
        total_weight += w

    if total_weight > 0:
        return round(weighted_score / total_weight, 1)
    return 0


def get_threat_level(score):
    """Return a human-readable threat level label."""
    if score >= 75:
        return 'CRITICAL'
    elif score >= 50:
        return 'HIGH'
    elif score >= 25:
        return 'MEDIUM'
    elif score > 0:
        return 'LOW'
    else:
        return 'CLEAN'


# --- Containment Script Generator ---
def generate_containment(ioc, ioc_type):
    """Generate containment scripts for firewall / EDR."""
    scripts = {}

    if ioc_type == 'ip':
        scripts['iptables'] = f'sudo iptables -A INPUT -s {ioc} -j DROP\nsudo iptables -A OUTPUT -d {ioc} -j DROP'
        scripts['windows_firewall'] = f'netsh advfirewall firewall add rule name="Block {ioc}" dir=in action=block remoteip={ioc}\nnetsh advfirewall firewall add rule name="Block {ioc}" dir=out action=block remoteip={ioc}'
        scripts['snort'] = f'drop ip {ioc} any -> $HOME_NET any (msg:"ThreatLens: Blocked malicious IP {ioc}"; sid:1000001; rev:1;)'
        scripts['paloalto'] = f'set address "ThreatLens-{ioc}" ip-netmask {ioc}/32\nset security policies deny-threatlens from any to any source "ThreatLens-{ioc}" action deny'

    elif ioc_type == 'domain':
        scripts['bind_rpz'] = f'; Add to RPZ zone file\n{ioc} CNAME .\n*.{ioc} CNAME .'
        scripts['windows_hosts'] = f'# Add to C:\\Windows\\System32\\drivers\\etc\\hosts\n0.0.0.0 {ioc}\n0.0.0.0 www.{ioc}'
        scripts['snort'] = f'alert dns any any -> any any (msg:"ThreatLens: DNS query for malicious domain {ioc}"; content:"{ioc}"; nocase; sid:1000002; rev:1;)'
        scripts['paloalto'] = f'set profiles custom-url-category "ThreatLens-Blocked" list "{ioc}"\nset security policies deny-domain from any to any url-category "ThreatLens-Blocked" action deny'

    elif ioc_type == 'hash':
        scripts['yara'] = f'rule ThreatLens_MalwareHash {{\n    meta:\n        description = "Block file by hash - ThreatLens"\n        hash = "{ioc}"\n    condition:\n        hash.md5(0, filesize) == "{ioc}" or\n        hash.sha256(0, filesize) == "{ioc}"\n}}'
        scripts['windows_defender'] = f'# Block hash in Windows Defender\nAdd-MpPreference -ThreatIDDefaultAction_Actions 6 -ThreatIDDefaultAction_Ids 2147001234\n# Manual quarantine:\nSet-MpPreference -ExclusionExtension ""\n# Hash: {ioc}'
        scripts['osquery'] = f"SELECT * FROM hash WHERE md5 = '{ioc}' OR sha256 = '{ioc}';"

    elif ioc_type == 'email':
        domain = ioc.split('@')[1] if '@' in ioc else 'unknown'
        scripts['exchange_block'] = f'# Block sender in Exchange Online\nNew-TransportRule -Name "Block {ioc}" -SenderAddressLocation Header -From "{ioc}" -DeleteMessage $true'
        scripts['gmail_filter'] = f'# Gmail Admin Console filter\nfrom:{ioc} → delete / quarantine'
        scripts['postfix_block'] = f'# Add to /etc/postfix/sender_access\n{ioc} REJECT Blocked by ThreatLens TI\n{domain} REJECT Blocked domain by ThreatLens TI\n# Then run: postmap /etc/postfix/sender_access && systemctl reload postfix'

    return scripts


# --- Flask Routes ---

@app.route('/')
def index():
    """Serve the main UI."""
    return render_template('index.html')


def perform_lookup_core(query):
    """Core logic to perform lookup on a single IOC, with caching support."""
    query = query.strip()
    if not query:
        return {'error': 'Empty query'}

    if len(query) > MAX_QUERY_LENGTH:
        return {'error': f'Query too long (max {MAX_QUERY_LENGTH} characters)'}

    # Sanitize: only allow alphanumeric, dots, colons, hyphens, @, underscores
    if not re.match(r'^[a-zA-Z0-9.:@_\-]+$', query):
        return {'error': 'Query contains invalid characters'}

    ioc_type = detect_ioc_type(query)
    if ioc_type == 'unknown':
        return {'error': f'Could not detect IOC type for: {query}'}

    # Check cache first
    cache_key = f'lookup_{hashlib.md5(query.encode()).hexdigest()}'
    cached = cache.get(cache_key)
    if cached:
        cached['from_cache'] = True
        return cached

    # Query only applicable APIs in parallel
    supported_types = {
        'virustotal': ['ip', 'domain', 'hash'],
        'abuseipdb': ['ip'],
        'ipinfo': ['ip'],
        'otx': ['ip', 'domain', 'hash'],
        'emailrep': ['email'],
        'hunterio': ['email'],
        'urlscan': ['ip', 'domain'],
        'domain_checker': ['domain'],
        'dns_history': ['domain']
    }

    results = []
    applicable_queries = []
    query_functions = [
        ('virustotal', query_virustotal),
        ('abuseipdb', query_abuseipdb),
        ('ipinfo', query_ipinfo),
        ('otx', query_otx_alienvault),
        ('emailrep', query_emailrep),
        ('hunterio', query_hunterio),
        ('urlscan', query_urlscan),
        ('domain_checker', query_domain_checker),
        ('dns_history', query_dns_history),
    ]

    for name, func in query_functions:
        if ioc_type in supported_types.get(name, []):
            applicable_queries.append((name, func))
        else:
            results.append({
                'source': name,
                'success': True,
                'error': None,
                'data': {
                    'not_applicable': True,
                    'message': f'{name} does not support {ioc_type} lookups'
                }
            })

    if applicable_queries:
        with ThreadPoolExecutor(max_workers=len(applicable_queries)) as executor:
            futures = {}
            for name, func in applicable_queries:
                future = executor.submit(func, query, ioc_type)
                futures[future] = name

            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    source_name = futures[future]
                    results.append({
                        'source': source_name,
                        'success': False,
                        'error': str(e)[:200],
                        'data': None
                    })

    # Calculate unified score
    unified_score = calculate_unified_score(results)
    threat_level = get_threat_level(unified_score)

    # Generate containment scripts
    containment = generate_containment(query, ioc_type)

    # Check which API keys are configured
    api_status_data = {
        'virustotal': bool(VT_API_KEY),
        'abuseipdb': bool(ABUSE_API_KEY),
        'ipinfo': bool(IPINFO_API_KEY),
        'otx': bool(OTX_API_KEY),
        'hunterio': bool(HUNTER_API_KEY),
        'urlscan': bool(URLSCAN_API_KEY),
        'domain_checker': True,  # free RDAP, no key
        'emailrep': True,  # No key needed
        'dns_history': True
    }

    response_data = {
        'query': query,
        'ioc_type': ioc_type,
        'unified_score': unified_score,
        'threat_level': threat_level,
        'results': results,
        'containment': containment,
        'api_status': api_status_data,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
        'from_cache': False
    }

    # Cache for 5 minutes
    cache.set(cache_key, response_data, timeout=300)

    return response_data


def get_ioc_summary(ioc_type, results):
    """Extract a quick summary string (ISP, Owner, Registrar, etc.) for bulk results."""
    for r in results:
        if not r.get('success') or not r.get('data'):
            continue
        d = r['data']
        if d.get('not_applicable'):
            continue
        if ioc_type == 'ip':
            if r['source'] == 'ipinfo' and d.get('org'):
                return d['org']
            if r['source'] == 'abuseipdb' and d.get('isp'):
                return d['isp']
            if r['source'] == 'virustotal' and d.get('as_owner'):
                return d['as_owner']
        elif ioc_type == 'domain':
            if r['source'] == 'domain_checker' and d.get('registrar'):
                return f"Registrar: {d['registrar']}"
            if r['source'] == 'virustotal' and d.get('registrar'):
                return f"Registrar: {d['registrar']}"
        elif ioc_type == 'hash':
            if r['source'] == 'virustotal' and d.get('file_name'):
                return f"{d.get('file_type', 'File')}: {d['file_name']}"
        elif ioc_type == 'email':
            if r['source'] == 'emailrep':
                return f"Reputation: {d.get('reputation', 'Unknown')}"
    return 'N/A'


@app.route('/api/lookup', methods=['POST'])
@limiter.limit('15 per minute')
def lookup():
    """Main IOC lookup endpoint."""
    body = request.get_json()
    if not body or not body.get('query'):
        return jsonify({'error': 'Missing query parameter'}), 400

    result = perform_lookup_core(body['query'])
    if 'error' in result:
        return jsonify(result), 400

    return jsonify(result)


@app.route('/api/lookup/bulk', methods=['POST'])
@limiter.limit('10 per minute')
def lookup_bulk():
    """Bulk IOC lookup endpoint. Queries up to 15 IOCs in parallel."""
    body = request.get_json()
    if not body or not body.get('queries') or not isinstance(body['queries'], list):
        return jsonify({'error': 'Missing list of queries'}), 400

    queries = [q.strip() for q in body['queries'] if q and q.strip()][:15]
    if not queries:
        return jsonify({'error': 'No valid queries provided'}), 400

    logger.info(f"Bulk Lookup: Processing {len(queries)} IOCs")

    bulk_results = []
    # Query all IOCs in parallel using thread pool
    with ThreadPoolExecutor(max_workers=min(len(queries), 8)) as executor:
        futures = {executor.submit(perform_lookup_core, q): q for q in queries}

        for future in as_completed(futures):
            query = futures[future]
            try:
                res = future.result()
                if 'error' in res:
                    bulk_results.append({
                        'query': query,
                        'ioc_type': 'unknown',
                        'success': False,
                        'error': res['error'],
                        'unified_score': 0,
                        'threat_level': 'UNKNOWN',
                        'summary': 'N/A'
                    })
                else:
                    summary = get_ioc_summary(res['ioc_type'], res['results'])
                    bulk_results.append({
                        'query': res['query'],
                        'ioc_type': res['ioc_type'],
                        'success': True,
                        'error': None,
                        'unified_score': res['unified_score'],
                        'threat_level': res['threat_level'],
                        'summary': summary
                    })
            except Exception as e:
                bulk_results.append({
                    'query': query,
                    'ioc_type': 'unknown',
                    'success': False,
                    'error': str(e)[:200],
                    'unified_score': 0,
                    'threat_level': 'UNKNOWN',
                    'summary': 'N/A'
                })

    # Sort results in the order of original queries list for consistency
    bulk_results.sort(key=lambda x: queries.index(x['query']) if x['query'] in queries else 99)

    return jsonify({
        'results': bulk_results,
        'count': len(bulk_results),
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
    })


@app.route('/api/export/csv', methods=['POST'])
@limiter.limit('10 per minute')
def export_csv():
    """Export scan results as CSV."""
    body = request.get_json()
    if not body or not body.get('results'):
        return jsonify({'error': 'No results to export'}), 400

    output = io.StringIO()
    writer = csv.writer(output)

    query = body.get('query', 'unknown')
    ioc_type = body.get('ioc_type', 'unknown')
    score = body.get('unified_score', 0)
    threat_level = body.get('threat_level', 'UNKNOWN')
    timestamp = body.get('timestamp', '')

    # Header info
    writer.writerow(['ThreatLens TI — IOC Scan Report'])
    writer.writerow(['IOC', query])
    writer.writerow(['Type', ioc_type.upper()])
    writer.writerow(['Unified Score', f'{score}/100'])
    writer.writerow(['Threat Level', threat_level])
    writer.writerow(['Scan Time', timestamp])
    writer.writerow([])

    # Per-source results
    writer.writerow(['Source', 'Status', 'Score', 'Key Findings'])
    for r in body.get('results', []):
        source = r.get('source', 'unknown')
        if not r.get('success'):
            writer.writerow([source, 'ERROR', '', r.get('error', '')])
            continue
        data = r.get('data', {})
        if data.get('not_applicable'):
            writer.writerow([source, 'N/A', '', data.get('message', '')])
            continue
        if data.get('found') is False:
            writer.writerow([source, 'NOT FOUND', '', data.get('message', '')])
            continue

        src_score = data.get('score', 0)
        # Collect key findings
        findings = []
        for k, v in data.items():
            if k in ('score', 'found', 'ioc_type', 'not_applicable'):
                continue
            if isinstance(v, (list, dict)):
                continue
            if v and v != 'N/A' and v != 'Unknown' and v is not False:
                findings.append(f'{k}={v}')
        writer.writerow([source, 'OK', src_score, '; '.join(findings[:8])])

    csv_output = output.getvalue()
    output.close()

    return Response(
        csv_output,
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=threatlens_{query}_{ioc_type}.csv'}
    )


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring."""
    return jsonify({
        'status': 'healthy',
        'service': 'ThreatLens TI',
        'version': '1.1.0',
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
        'api_keys_configured': {
            'virustotal': bool(VT_API_KEY),
            'abuseipdb': bool(ABUSE_API_KEY),
            'ipinfo': bool(IPINFO_API_KEY),
            'otx': bool(OTX_API_KEY),
            'hunterio': bool(HUNTER_API_KEY),
            'urlscan': bool(URLSCAN_API_KEY),
        }
    })


@app.route('/api/status', methods=['GET'])
def api_status():
    """Check which API keys are configured."""
    return jsonify({
        'virustotal': bool(VT_API_KEY),
        'abuseipdb': bool(ABUSE_API_KEY),
        'ipinfo': bool(IPINFO_API_KEY),
        'otx': bool(OTX_API_KEY),
        'hunterio': bool(HUNTER_API_KEY),
        'urlscan': bool(URLSCAN_API_KEY),
        'domain_checker': True,
        'emailrep': True
    })


if __name__ == '__main__':
    print("\n" + "="*60)
    print("  ThreatLens TI — Multi-Source Threat Intelligence Platform")
    print("="*60)
    print(f"  VirusTotal API Key: {'✓ Configured' if VT_API_KEY else '✗ Missing'}")
    print(f"  AbuseIPDB API Key:  {'✓ Configured' if ABUSE_API_KEY else '✗ Missing'}")
    print(f"  IPInfo API Key:     {'✓ Configured' if IPINFO_API_KEY else '✗ Missing'}")
    print(f"  OTX API Key:        {'✓ Configured' if OTX_API_KEY else '✗ Missing'}")
    print(f"  Hunter.io API Key:  {'✓ Configured' if HUNTER_API_KEY else '✗ Missing'}")
    print(f"  URLScan API Key:    {'✓ Configured' if URLSCAN_API_KEY else '✗ Missing (Optional)'}")
    print(f"  Domain Checker:      ✓ Free (RDAP, no key needed)")
    print(f"  EmailRep.io:         ✓ Free (no key needed)")
    print("="*60)
    print("  Open http://localhost:5000 in your browser")
    print("="*60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)
