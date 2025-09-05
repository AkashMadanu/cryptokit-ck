"""
Security scanner for CryptoKit (CK)

Security analysis including suspicious pattern detection, 
anomaly detection, and behavioral analysis.
"""

import os
import re
import hashlib
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from datetime import datetime


class SecurityScanner:
    """
    Security scanner for file analysis.
    
    Detects suspicious patterns, potential malware indicators,
    and security anomalies in files.
    """
    
    def __init__(self):
        """Initialize the security scanner."""
        # Known malicious patterns (simplified examples)
        self.malicious_patterns = {
            'suspicious_urls': [
                r'bit\.ly/', r'tinyurl\.com/', r't\.co/',
                r'[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', # IP addresses
            ],
            'suspicious_commands': [
                'powershell', 'cmd.exe', '/bin/sh', '/bin/bash',
                'wget', 'curl', 'nc ', 'netcat', 'telnet'
            ],
            'file_operations': [
                'CreateFile', 'WriteFile', 'DeleteFile', 'CopyFile',
                'fopen', 'fwrite', 'remove', 'unlink'
            ],
            'registry_operations': [
                'RegOpenKey', 'RegSetValue', 'RegDeleteKey',
                'HKEY_LOCAL_MACHINE', 'HKEY_CURRENT_USER'
            ],
            'network_operations': [
                'socket', 'connect', 'send', 'recv', 'bind', 'listen',
                'HttpSendRequest', 'InternetOpen', 'URLDownloadToFile'
            ],
            'crypto_operations': [
                'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext',
                'AES', 'RSA', 'base64', 'encrypt', 'decrypt'
            ]
        }
        
        # Suspicious file extensions
        self.suspicious_extensions = {
            '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', 
            '.js', '.jar', '.ps1', '.dll', '.sys', '.tmp'
        }
        
        # Common vulnerability patterns
        self.vulnerability_patterns = [
            r'buffer\s*overflow',
            r'sql\s*injection',
            r'xss', r'cross\s*site\s*scripting',
            r'path\s*traversal', r'\.\./',
            r'format\s*string',
            r'use\s*after\s*free',
            r'double\s*free'
        ]
    
    def scan_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Perform comprehensive security scan of a file.
        
        Args:
            file_path: Path to file to scan
            
        Returns:
            Dictionary with security scan results
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        result = {
            'file_path': str(file_path),
            'scan_timestamp': datetime.now().isoformat(),
            'file_info': self._analyze_file_metadata(file_path)
        }
        
        # File content analysis
        try:
            with open(file_path, 'rb') as f:
                raw_content = f.read()
            
            result['content_scan'] = self._scan_content(raw_content)
            result['pattern_analysis'] = self._analyze_patterns(raw_content)
            result['hash_analysis'] = self._analyze_hashes(raw_content)
            
            # Try text analysis if possible
            try:
                text_content = raw_content.decode('utf-8', errors='ignore')
                result['text_scan'] = self._scan_text_content(text_content)
                result['vulnerability_scan'] = self._scan_vulnerabilities(text_content)
            except:
                result['text_scan'] = {'status': 'failed', 'reason': 'Could not decode as text'}
                result['vulnerability_scan'] = {'status': 'skipped', 'reason': 'Binary file'}
        
        except Exception as e:
            result['content_scan'] = {'status': 'failed', 'error': str(e)}
        
        # Calculate overall risk score
        result['risk_assessment'] = self._calculate_risk_score(result)
        
        return result
    
    def _analyze_file_metadata(self, file_path: Path) -> Dict[str, Any]:
        """Analyze file metadata for security indicators."""
        try:
            stat = file_path.stat()
            
            # Check for suspicious characteristics
            suspicious_indicators = []
            
            # Check extension
            if file_path.suffix.lower() in self.suspicious_extensions:
                suspicious_indicators.append(f"Suspicious extension: {file_path.suffix}")
            
            # Check if file is executable
            if os.access(file_path, os.X_OK):
                suspicious_indicators.append("File is executable")
            
            # Check for hidden file (starts with .)
            if file_path.name.startswith('.') and file_path.name != '.' and file_path.name != '..':
                suspicious_indicators.append("Hidden file")
            
            # Check for very large or very small files
            size = stat.st_size
            if size == 0:
                suspicious_indicators.append("Zero-byte file")
            elif size > 100 * 1024 * 1024:  # > 100MB
                suspicious_indicators.append("Very large file")
            
            # Check timestamps for anomalies
            now = datetime.now().timestamp()
            if stat.st_mtime > now:
                suspicious_indicators.append("Future modification time")
            
            return {
                'file_size': size,
                'permissions': oct(stat.st_mode)[-3:],
                'is_executable': os.access(file_path, os.X_OK),
                'creation_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modification_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'access_time': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'suspicious_indicators': suspicious_indicators,
                'risk_level': 'high' if len(suspicious_indicators) > 2 else 'medium' if suspicious_indicators else 'low'
            }
            
        except Exception as e:
            return {'error': f"Metadata analysis failed: {e}"}
    
    def _scan_content(self, content: bytes) -> Dict[str, Any]:
        """Scan raw content for security indicators."""
        indicators = []
        
        # Check for common malware signatures
        malware_signatures = [
            b'This program cannot be run in DOS mode',
            b'kernel32.dll',
            b'LoadLibrary',
            b'GetProcAddress',
            b'VirtualAlloc',
            b'CreateThread',
            b'ShellExecute',
        ]
        
        for sig in malware_signatures:
            if sig in content:
                indicators.append(f"Contains signature: {sig.decode('ascii', errors='ignore')}")
        
        # Check for encoded content
        if len(content) > 0:
            # Look for high concentration of base64-like characters
            b64_chars = sum(1 for b in content if chr(b) in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            if b64_chars / len(content) > 0.75:
                indicators.append("High concentration of base64-like characters")
            
            # Look for hex patterns
            hex_pattern = re.compile(rb'(?:[0-9a-fA-F]{2}\s*){20,}')
            if hex_pattern.search(content):
                indicators.append("Contains long hexadecimal sequences")
        
        # Check for packer/obfuscation indicators
        packed_indicators = [b'UPX', b'MPRESS', b'ASPack', b'PECompact']
        for indicator in packed_indicators:
            if indicator in content:
                indicators.append(f"Possible packer: {indicator.decode('ascii', errors='ignore')}")
        
        return {
            'indicators_found': len(indicators),
            'indicators': indicators,
            'content_size': len(content),
            'risk_level': 'high' if len(indicators) > 3 else 'medium' if len(indicators) > 1 else 'low'
        }
    
    def _analyze_patterns(self, content: bytes) -> Dict[str, Any]:
        """Analyze content for suspicious patterns."""
        try:
            # Convert to text for pattern matching
            text_content = content.decode('utf-8', errors='ignore')
        except:
            return {'status': 'skipped', 'reason': 'Could not decode content'}
        
        pattern_results = {}
        
        for category, patterns in self.malicious_patterns.items():
            matches = []
            for pattern in patterns:
                if isinstance(pattern, str):
                    # Simple string search
                    if pattern.lower() in text_content.lower():
                        matches.append(pattern)
                else:
                    # Regex search
                    regex_matches = re.findall(pattern, text_content, re.IGNORECASE)
                    matches.extend(regex_matches)
            
            if matches:
                pattern_results[category] = {
                    'count': len(matches),
                    'matches': matches[:5]  # Limit to first 5
                }
        
        total_matches = sum(result['count'] for result in pattern_results.values())
        
        return {
            'total_patterns_found': total_matches,
            'categories_found': len(pattern_results),
            'pattern_details': pattern_results,
            'risk_level': 'high' if total_matches > 10 else 'medium' if total_matches > 3 else 'low'
        }
    
    def _analyze_hashes(self, content: bytes) -> Dict[str, Any]:
        """Analyze file hashes and look for known bad hashes."""
        try:
            # Calculate multiple hashes
            md5_hash = hashlib.md5(content).hexdigest()
            sha1_hash = hashlib.sha1(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
            
            # This is where you could check against threat intelligence feeds
            # For now, we'll do basic analysis
            
            # Check for empty file
            if md5_hash == 'd41d8cd98f00b204e9800998ecf8427e':  # Empty file MD5
                warning = 'Empty file detected'
            else:
                warning = None
            
            return {
                'md5': md5_hash,
                'sha1': sha1_hash,
                'sha256': sha256_hash,
                'warning': warning,
                'threat_intelligence': 'Not implemented - would check against threat feeds'
            }
            
        except Exception as e:
            return {'error': f"Hash analysis failed: {e}"}
    
    def _scan_text_content(self, text: str) -> Dict[str, Any]:
        """Scan text content for suspicious elements."""
        suspicious_elements = []
        
        # Look for suspicious URLs
        url_pattern = re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE)
        urls = url_pattern.findall(text)
        
        # Check URLs against suspicious patterns
        suspicious_urls = []
        for url in urls:
            for pattern in self.malicious_patterns['suspicious_urls']:
                if re.search(pattern, url, re.IGNORECASE):
                    suspicious_urls.append(url)
        
        if suspicious_urls:
            suspicious_elements.append(f"Suspicious URLs found: {len(suspicious_urls)}")
        
        # Look for credentials or sensitive data
        credential_patterns = [
            r'password\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            r'api[_-]?key\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            r'secret\s*[:=]\s*["\']?([^"\'\s]+)["\']?',
            r'token\s*[:=]\s*["\']?([^"\'\s]+)["\']?'
        ]
        
        credentials_found = []
        for pattern in credential_patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            credentials_found.extend(matches)
        
        if credentials_found:
            suspicious_elements.append(f"Potential credentials found: {len(credentials_found)}")
        
        # Look for obfuscated code
        obfuscation_indicators = [
            r'eval\s*\(',
            r'exec\s*\(',
            r'\\x[0-9a-fA-F]{2}',  # Hex escape sequences
            r'\\[0-7]{3}',         # Octal escape sequences
            r'String\.fromCharCode',
            r'unescape\s*\(',
            r'document\.write\s*\('
        ]
        
        obfuscation_found = []
        for pattern in obfuscation_indicators:
            if re.search(pattern, text, re.IGNORECASE):
                obfuscation_found.append(pattern)
        
        if obfuscation_found:
            suspicious_elements.append(f"Obfuscation indicators: {len(obfuscation_found)}")
        
        return {
            'suspicious_elements': suspicious_elements,
            'urls_found': len(urls),
            'suspicious_urls': suspicious_urls[:5],  # Limit display
            'credentials_count': len(credentials_found),
            'obfuscation_indicators': obfuscation_found,
            'risk_level': 'high' if len(suspicious_elements) > 3 else 'medium' if suspicious_elements else 'low'
        }
    
    def _scan_vulnerabilities(self, text: str) -> Dict[str, Any]:
        """Scan for known vulnerability patterns."""
        vulnerabilities_found = []
        
        for pattern in self.vulnerability_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                vulnerabilities_found.append(pattern)
        
        # Additional checks for common vulnerability indicators
        vuln_indicators = []
        
        # SQL injection indicators
        sql_patterns = [
            r"union\s+select", r"drop\s+table", r"insert\s+into",
            r"delete\s+from", r"update\s+.*\s+set", r"--\s*$"
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, text, re.IGNORECASE | re.MULTILINE):
                vuln_indicators.append(f"SQL injection pattern: {pattern}")
        
        # XSS indicators
        xss_patterns = [
            r"<script[^>]*>", r"javascript:", r"onerror\s*=",
            r"onload\s*=", r"eval\s*\(", r"document\.cookie"
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                vuln_indicators.append(f"XSS pattern: {pattern}")
        
        # Path traversal
        if re.search(r'\.\./', text) or re.search(r'\.\.\\', text):
            vuln_indicators.append("Path traversal pattern")
        
        return {
            'vulnerability_patterns': vulnerabilities_found,
            'vulnerability_indicators': vuln_indicators,
            'total_vulnerabilities': len(vulnerabilities_found) + len(vuln_indicators),
            'risk_level': 'high' if len(vuln_indicators) > 5 else 'medium' if vuln_indicators else 'low'
        }
    
    def _calculate_risk_score(self, scan_result: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall risk score based on all scan results."""
        risk_factors = []
        total_score = 0
        
        # File metadata risk
        if 'file_info' in scan_result and 'suspicious_indicators' in scan_result['file_info']:
            metadata_indicators = len(scan_result['file_info']['suspicious_indicators'])
            if metadata_indicators > 0:
                risk_factors.append(f"File metadata: {metadata_indicators} indicators")
                total_score += metadata_indicators * 10
        
        # Content scan risk
        if 'content_scan' in scan_result and 'indicators_found' in scan_result['content_scan']:
            content_indicators = scan_result['content_scan']['indicators_found']
            if content_indicators > 0:
                risk_factors.append(f"Content scan: {content_indicators} indicators")
                total_score += content_indicators * 15
        
        # Pattern analysis risk
        if 'pattern_analysis' in scan_result and 'total_patterns_found' in scan_result['pattern_analysis']:
            pattern_count = scan_result['pattern_analysis']['total_patterns_found']
            if pattern_count > 0:
                risk_factors.append(f"Suspicious patterns: {pattern_count} found")
                total_score += pattern_count * 5
        
        # Text scan risk
        if 'text_scan' in scan_result and 'suspicious_elements' in scan_result['text_scan']:
            text_elements = len(scan_result['text_scan']['suspicious_elements'])
            if text_elements > 0:
                risk_factors.append(f"Text analysis: {text_elements} elements")
                total_score += text_elements * 8
        
        # Vulnerability scan risk
        if 'vulnerability_scan' in scan_result and 'total_vulnerabilities' in scan_result['vulnerability_scan']:
            vuln_count = scan_result['vulnerability_scan']['total_vulnerabilities']
            if vuln_count > 0:
                risk_factors.append(f"Vulnerabilities: {vuln_count} found")
                total_score += vuln_count * 20
        
        # Determine overall risk level
        if total_score >= 100:
            risk_level = 'CRITICAL'
        elif total_score >= 50:
            risk_level = 'HIGH'
        elif total_score >= 20:
            risk_level = 'MEDIUM'
        elif total_score > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'MINIMAL'
        
        return {
            'risk_score': total_score,
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'recommendation': self._get_recommendation(risk_level),
            'scan_summary': f"{len(risk_factors)} risk categories identified"
        }
    
    def _get_recommendation(self, risk_level: str) -> str:
        """Get security recommendation based on risk level."""
        recommendations = {
            'CRITICAL': 'IMMEDIATE ACTION REQUIRED: File shows multiple high-risk indicators. Quarantine and analyze in isolated environment.',
            'HIGH': 'HIGH RISK: File contains concerning patterns. Scan with updated antivirus and avoid execution.',
            'MEDIUM': 'MODERATE RISK: File has some suspicious characteristics. Exercise caution and verify source.',
            'LOW': 'LOW RISK: Minor indicators found. Generally safe but monitor for changes.',
            'MINIMAL': 'MINIMAL RISK: No significant threats detected. File appears clean.'
        }
        return recommendations.get(risk_level, 'Unknown risk level')
    
    def get_scan_summary(self, scan_result: Dict[str, Any]) -> str:
        """
        Generate human-readable summary of security scan.
        
        Args:
            scan_result: Result from scan_file()
            
        Returns:
            Human-readable summary string
        """
        if 'risk_assessment' not in scan_result:
            return "Security scan failed or incomplete"
        
        risk = scan_result['risk_assessment']
        file_info = scan_result.get('file_info', {})
        
        summary_parts = [
            f"Risk Level: {risk['risk_level']}",
            f"Score: {risk['risk_score']}/100",
            f"Factors: {len(risk['risk_factors'])}"
        ]
        
        if file_info.get('file_size'):
            size_mb = file_info['file_size'] / (1024 * 1024)
            summary_parts.append(f"Size: {size_mb:.2f}MB")
        
        return " | ".join(summary_parts)
