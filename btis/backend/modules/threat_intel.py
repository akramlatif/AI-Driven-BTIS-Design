"""
Threat Intelligence Module for BTIS
Integrates external threat intelligence and maintains threat indicators
"""

import logging
import requests
from datetime import datetime, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)

class ThreatIntelligence:
    """
    Threat Intelligence Integration
    Manages IOCs, threat feeds, and reputation data
    """
    
    def __init__(self):
        self.threat_indicators = {
            'ips': set(),
            'domains': set(),
            'file_hashes': set(),
            'user_agents': set()
        }
        
        # Reputation cache
        self.reputation_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        logger.info("Threat Intelligence module initialized")
    
    def check_ip_reputation(self, ip_address):
        """
        Check reputation of an IP address
        
        Returns:
            dict with reputation info
        """
        if not ip_address:
            return {'reputation': 'unknown', 'score': 0}
        
        # Check cache
        cache_key = f"ip:{ip_address}"
        if cache_key in self.reputation_cache:
            cached = self.reputation_cache[cache_key]
            if datetime.utcnow() - cached['timestamp'] < timedelta(seconds=self.cache_ttl):
                return cached['data']
        
        # Check internal threat list
        if ip_address in self.threat_indicators['ips']:
            result = {'reputation': 'bad', 'score': 100, 'source': 'internal'}
        else:
            # Simulate external check
            result = self._simulate_ip_check(ip_address)
        
        # Cache result
        self.reputation_cache[cache_key] = {
            'data': result,
            'timestamp': datetime.utcnow()
        }
        
        return result
    
    def _simulate_ip_check(self, ip_address):
        """Simulate external IP reputation check"""
        # In production, this would query services like VirusTotal, AbuseIPDB, etc.
        
        # Known internal ranges are trusted
        if ip_address.startswith(('10.', '192.168.', '172.16.')):
            return {'reputation': 'good', 'score': 0, 'source': 'internal_network'}
        
        # Simulate some bad IPs for demo
        bad_ips = ['192.0.2.100', '198.51.100.50', '203.0.113.25']
        if ip_address in bad_ips:
            return {
                'reputation': 'bad',
                'score': 85,
                'source': 'simulated_threat_feed',
                'categories': ['malware', 'botnet'],
                'last_seen': datetime.utcnow().isoformat()
            }
        
        return {'reputation': 'neutral', 'score': 30, 'source': 'default'}
    
    def check_file_hash(self, file_hash):
        """Check if file hash is known malicious"""
        if file_hash in self.threat_indicators['file_hashes']:
            return {'reputation': 'malicious', 'score': 100}
        
        return {'reputation': 'unknown', 'score': 0}
    
    def add_threat_indicator(self, indicator_type, value, metadata=None):
        """Add a threat indicator"""
        if indicator_type in self.threat_indicators:
            self.threat_indicators[indicator_type].add(value)
            logger.info(f"Added {indicator_type} threat indicator: {value}")
            return True
        return False
    
    def remove_threat_indicator(self, indicator_type, value):
        """Remove a threat indicator"""
        if indicator_type in self.threat_indicators:
            self.threat_indicators[indicator_type].discard(value)
            return True
        return False
    
    def get_threat_stats(self):
        """Get threat intelligence statistics"""
        return {
            'indicators': {
                'malicious_ips': len(self.threat_indicators['ips']),
                'malicious_domains': len(self.threat_indicators['domains']),
                'malicious_hashes': len(self.threat_indicators['file_hashes']),
                'suspicious_user_agents': len(self.threat_indicators['user_agents'])
            },
            'cache_size': len(self.reputation_cache),
            'last_updated': datetime.utcnow().isoformat()
        }
    
    def analyze_behavior_threats(self, user_id, behavior_logs):
        """
        Analyze behavior logs for threat indicators
        
        Returns:
            List of detected threats
        """
        threats = []
        
        # Check for known malicious IPs
        for log in behavior_logs:
            if log.ip_address:
                rep = self.check_ip_reputation(log.ip_address)
                if rep['reputation'] == 'bad':
                    threats.append({
                        'type': 'malicious_ip',
                        'severity': 'high',
                        'indicator': log.ip_address,
                        'timestamp': log.timestamp.isoformat(),
                        'details': rep
                    })
        
        # Check for attack patterns
        attack_patterns = self._detect_attack_patterns(behavior_logs)
        threats.extend(attack_patterns)
        
        return threats
    
    def _detect_attack_patterns(self, logs):
        """Detect known attack patterns in logs"""
        threats = []
        
        # Pattern: Brute force login attempts
        login_logs = [log for log in logs if log.action_type == 'login']
        failed_logins = [log for log in logs if log.action_type == 'failed_login']
        
        if len(failed_logins) > 5:
            threats.append({
                'type': 'brute_force_attempt',
                'severity': 'medium',
                'indicator': 'multiple_failed_logins',
                'count': len(failed_logins),
                'details': {'failed': len(failed_logins), 'successful': len(login_logs)}
            })
        
        # Pattern: Data exfiltration
        download_logs = [log for log in logs if log.action_type == 'file_download']
        sensitive_downloads = [log for log in download_logs 
                              if log.sensitivity_level in ['high', 'critical']]
        
        if len(sensitive_downloads) > 3:
            threats.append({
                'type': 'potential_exfiltration',
                'severity': 'high',
                'indicator': 'sensitive_file_downloads',
                'count': len(sensitive_downloads),
                'details': {'total_downloads': len(download_logs), 'sensitive': len(sensitive_downloads)}
            })
        
        # Pattern: Privilege escalation
        priv_esc_logs = [log for log in logs if log.action_type == 'privilege_escalation']
        if priv_esc_logs:
            threats.append({
                'type': 'privilege_escalation',
                'severity': 'critical',
                'indicator': 'privilege_escalation_attempt',
                'count': len(priv_esc_logs),
                'details': {'attempts': len(priv_esc_logs)}
            })
        
        # Pattern: After-hours sensitive access
        after_hours_sensitive = []
        for log in logs:
            if log.sensitivity_level in ['high', 'critical']:
                hour = log.timestamp.hour
                if hour < 7 or hour > 20:
                    after_hours_sensitive.append(log)
        
        if len(after_hours_sensitive) > 2:
            threats.append({
                'type': 'after_hours_sensitive_access',
                'severity': 'medium',
                'indicator': 'after_hours_sensitive_access',
                'count': len(after_hours_sensitive),
                'details': {'access_count': len(after_hours_sensitive)}
            })
        
        return threats
    
    def get_risk_context(self, user_id, ip_address=None):
        """Get threat intelligence context for risk scoring"""
        context = {
            'ip_reputation': 'neutral',
            'known_threats': [],
            'attack_patterns': [],
            'risk_multiplier': 1.0
        }
        
        # Check IP reputation
        if ip_address:
            ip_rep = self.check_ip_reputation(ip_address)
            context['ip_reputation'] = ip_rep['reputation']
            context['ip_score'] = ip_rep['score']
            
            if ip_rep['reputation'] == 'bad':
                context['risk_multiplier'] = 1.5
            elif ip_rep['reputation'] == 'suspicious':
                context['risk_multiplier'] = 1.2
        
        return context
