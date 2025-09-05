"""
Content analysis for CryptoKit (CK)

Advanced content analysis including entropy calculation, string extraction,
and embedded file detection.
"""

import os
import re
import math
import string
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from collections import Counter
from datetime import datetime
import struct


class ContentAnalyzer:
    """
    Advanced content analyzer for file analysis.
    
    Provides entropy calculation, string extraction, pattern detection,
    and embedded content analysis.
    """
    
    def __init__(self):
        """Initialize the content analyzer."""
        # Common string patterns to detect
        self.string_patterns = {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'url': re.compile(r'https?://[^\s<>"\']+'),
            'ip_address': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
            'phone': re.compile(r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b'),
            'credit_card': re.compile(r'\b(?:[0-9]{4}[-\s]?){3}[0-9]{4}\b'),
            'social_security': re.compile(r'\b[0-9]{3}-?[0-9]{2}-?[0-9]{4}\b'),
            'hash_md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
            'hash_sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
            'hash_sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        }
    
    def analyze_content(self, file_path: Path, max_size: int = 10 * 1024 * 1024) -> Dict[str, Any]:
        """
        Perform comprehensive content analysis.
        
        Args:
            file_path: Path to file to analyze
            max_size: Maximum file size to analyze (default 10MB)
            
        Returns:
            Dictionary with analysis results
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_size = file_path.stat().st_size
        
        # Check file size limit
        if file_size > max_size:
            return {
                'file_path': str(file_path),
                'file_size': file_size,
                'analysis_skipped': True,
                'reason': f'File too large (>{max_size} bytes)',
                'max_size': max_size
            }
        
        result = {
            'file_path': str(file_path),
            'file_size': file_size,
            'analysis_skipped': False
        }
        
        # Read file content
        try:
            with open(file_path, 'rb') as f:
                raw_content = f.read()
        except Exception as e:
            return {
                'file_path': str(file_path),
                'error': f"Could not read file: {e}"
            }
        
        # Basic analysis
        result['entropy'] = self._calculate_entropy(raw_content)
        result['compression_analysis'] = self._analyze_compression(raw_content)
        result['binary_analysis'] = self._analyze_binary_content(raw_content)
        
        # Try text analysis if possible
        text_content = self._extract_text_content(raw_content)
        if text_content:
            result['text_analysis'] = self._analyze_text_content(text_content)
            result['string_extraction'] = self._extract_strings(text_content)
            result['pattern_detection'] = self._detect_patterns(text_content)
        
        # Look for embedded files
        result['embedded_analysis'] = self._detect_embedded_files(raw_content)
        
        # Security analysis
        result['security_indicators'] = self._analyze_security_indicators(raw_content, text_content)
        
        return result
    
    def _calculate_entropy(self, data: bytes) -> Dict[str, Any]:
        """
        Calculate Shannon entropy of the data.
        
        Args:
            data: Raw bytes to analyze
            
        Returns:
            Entropy analysis results
        """
        if not data:
            return {'entropy': 0.0, 'quality': 'empty'}
        
        # Count byte frequencies
        byte_counts = Counter(data)
        total_bytes = len(data)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in byte_counts.values():
            probability = count / total_bytes
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        # Classify entropy quality
        if entropy < 1.0:
            quality = 'very_low'
            description = 'Highly repetitive data'
        elif entropy < 3.0:
            quality = 'low'
            description = 'Some repetitive patterns'
        elif entropy < 6.0:
            quality = 'medium'
            description = 'Moderate randomness'
        elif entropy < 7.5:
            quality = 'high'
            description = 'High randomness'
        else:
            quality = 'very_high'
            description = 'Very high randomness (possibly encrypted/compressed)'
        
        return {
            'entropy': entropy,
            'max_entropy': 8.0,
            'quality': quality,
            'description': description,
            'unique_bytes': len(byte_counts),
            'total_bytes': total_bytes
        }
    
    def _analyze_compression(self, data: bytes) -> Dict[str, Any]:
        """Analyze compression characteristics."""
        try:
            import zlib
            
            # Try to compress with different levels
            compressed_data = zlib.compress(data, level=9)
            compression_ratio = len(compressed_data) / len(data) if data else 1.0
            
            # Analyze compression effectiveness
            if compression_ratio < 0.1:
                compression_quality = 'excellent'
                description = 'Data compresses very well (likely text/repetitive)'
            elif compression_ratio < 0.3:
                compression_quality = 'good'
                description = 'Data compresses well'
            elif compression_ratio < 0.7:
                compression_quality = 'moderate'
                description = 'Data compresses moderately'
            elif compression_ratio < 0.9:
                compression_quality = 'poor'
                description = 'Data compresses poorly (likely already compressed/encrypted)'
            else:
                compression_quality = 'very_poor'
                description = 'Data does not compress (likely encrypted/random)'
            
            return {
                'original_size': len(data),
                'compressed_size': len(compressed_data),
                'compression_ratio': compression_ratio,
                'space_saved': 1.0 - compression_ratio,
                'quality': compression_quality,
                'description': description
            }
            
        except Exception as e:
            return {'error': f"Compression analysis failed: {e}"}
    
    def _analyze_binary_content(self, data: bytes) -> Dict[str, Any]:
        """Analyze binary content characteristics."""
        if not data:
            return {'null_bytes': 0, 'printable_ratio': 0.0}
        
        # Count different types of bytes
        null_bytes = data.count(0)
        printable_bytes = sum(1 for b in data if 32 <= b <= 126)
        control_chars = sum(1 for b in data if b < 32 and b not in (9, 10, 13))
        extended_chars = sum(1 for b in data if b > 126)
        
        total_bytes = len(data)
        
        return {
            'null_bytes': null_bytes,
            'printable_bytes': printable_bytes,
            'control_chars': control_chars,
            'extended_chars': extended_chars,
            'total_bytes': total_bytes,
            'printable_ratio': printable_bytes / total_bytes,
            'null_ratio': null_bytes / total_bytes,
            'control_ratio': control_chars / total_bytes,
            'is_likely_binary': (null_bytes > 0) or (printable_bytes / total_bytes < 0.75)
        }
    
    def _extract_text_content(self, data: bytes) -> Optional[str]:
        """Extract text content from raw bytes."""
        try:
            # Try UTF-8 first
            return data.decode('utf-8')
        except UnicodeDecodeError:
            try:
                # Try Latin-1 as fallback
                return data.decode('latin-1', errors='ignore')
            except:
                # Extract only printable ASCII characters
                return ''.join(chr(b) for b in data if 32 <= b <= 126)
    
    def _analyze_text_content(self, text: str) -> Dict[str, Any]:
        """Analyze text content characteristics."""
        if not text:
            return {'char_count': 0, 'word_count': 0, 'line_count': 0}
        
        # Basic statistics
        char_count = len(text)
        word_count = len(text.split())
        line_count = text.count('\n') + 1
        
        # Character type analysis
        alpha_chars = sum(1 for c in text if c.isalpha())
        digit_chars = sum(1 for c in text if c.isdigit())
        space_chars = sum(1 for c in text if c.isspace())
        punct_chars = sum(1 for c in text if c in string.punctuation)
        
        # Language analysis (basic)
        alpha_ratio = alpha_chars / char_count if char_count > 0 else 0
        digit_ratio = digit_chars / char_count if char_count > 0 else 0
        
        # Detect possible language
        if alpha_ratio > 0.6:
            likely_language = 'text'
        elif digit_ratio > 0.5:
            likely_language = 'numeric_data'
        elif text.strip().startswith('{') and text.strip().endswith('}'):
            likely_language = 'json'
        elif text.strip().startswith('<') and text.strip().endswith('>'):
            likely_language = 'markup'
        else:
            likely_language = 'mixed'
        
        return {
            'char_count': char_count,
            'word_count': word_count,
            'line_count': line_count,
            'alpha_chars': alpha_chars,
            'digit_chars': digit_chars,
            'space_chars': space_chars,
            'punct_chars': punct_chars,
            'alpha_ratio': alpha_ratio,
            'digit_ratio': digit_ratio,
            'likely_language': likely_language,
            'avg_word_length': sum(len(word) for word in text.split()) / word_count if word_count > 0 else 0,
            'avg_line_length': char_count / line_count if line_count > 0 else 0
        }
    
    def _extract_strings(self, text: str, min_length: int = 4) -> Dict[str, Any]:
        """Extract interesting strings from text content."""
        if not text:
            return {'strings': [], 'count': 0}
        
        # Extract words/strings of minimum length
        words = re.findall(r'\b\w{' + str(min_length) + ',}\b', text)
        
        # Get most common strings
        word_counts = Counter(words)
        most_common = word_counts.most_common(20)
        
        # Extract long strings (potential base64, hex, etc.)
        long_strings = re.findall(r'\b[A-Za-z0-9+/=]{20,}\b', text)
        hex_strings = re.findall(r'\b[a-fA-F0-9]{16,}\b', text)
        
        return {
            'total_strings': len(words),
            'unique_strings': len(word_counts),
            'most_common': most_common,
            'long_strings': long_strings[:10],  # Limit to first 10
            'hex_strings': hex_strings[:10],
            'average_length': sum(len(word) for word in words) / len(words) if words else 0
        }
    
    def _detect_patterns(self, text: str) -> Dict[str, Any]:
        """Detect interesting patterns in text."""
        if not text:
            return {}
        
        results = {}
        
        for pattern_name, pattern in self.string_patterns.items():
            matches = pattern.findall(text)
            if matches:
                results[pattern_name] = {
                    'count': len(matches),
                    'matches': matches[:5]  # Limit to first 5 matches
                }
        
        return results
    
    def _detect_embedded_files(self, data: bytes) -> Dict[str, Any]:
        """Detect embedded files within the data."""
        embedded_files = []
        
        # Look for common file signatures within the data
        signatures = {
            b'PK\x03\x04': 'ZIP/Office Document',
            b'%PDF': 'PDF Document',
            b'\xFF\xD8\xFF': 'JPEG Image',
            b'\x89PNG': 'PNG Image',
            b'GIF8': 'GIF Image',
            b'RIFF': 'RIFF Container (AVI/WAV/etc.)',
            b'MZ': 'Windows Executable'
        }
        
        for sig, file_type in signatures.items():
            offset = 0
            while True:
                pos = data.find(sig, offset)
                if pos == -1:
                    break
                
                # Skip if it's at the beginning (main file signature)
                if pos > 0:
                    embedded_files.append({
                        'signature': sig.hex(),
                        'type': file_type,
                        'offset': pos,
                        'offset_hex': hex(pos)
                    })
                
                offset = pos + 1
        
        return {
            'embedded_files_found': len(embedded_files),
            'embedded_files': embedded_files
        }
    
    def _analyze_security_indicators(self, raw_data: bytes, text_data: Optional[str]) -> Dict[str, Any]:
        """Analyze for security-related indicators."""
        indicators = []
        
        # Check for suspicious binary patterns
        if raw_data:
            # Look for executable signatures
            if raw_data.startswith(b'MZ'):
                indicators.append('Contains Windows executable signature')
            if raw_data.startswith(b'\x7fELF'):
                indicators.append('Contains Linux executable signature')
            
            # Check for encryption indicators (high entropy)
            entropy_analysis = self._calculate_entropy(raw_data)
            if entropy_analysis['entropy'] > 7.5:
                indicators.append('Very high entropy - possibly encrypted or compressed')
        
        # Check text content for suspicious patterns
        if text_data:
            # Look for suspicious keywords
            suspicious_keywords = [
                'password', 'secret', 'api_key', 'private_key', 'token',
                'credentials', 'auth', 'passwd', 'admin', 'root'
            ]
            
            found_keywords = []
            for keyword in suspicious_keywords:
                if keyword.lower() in text_data.lower():
                    found_keywords.append(keyword)
            
            if found_keywords:
                indicators.append(f'Contains sensitive keywords: {", ".join(found_keywords)}')
            
            # Look for potential code injection
            code_patterns = ['<script', 'javascript:', 'eval(', 'exec(', 'system(']
            found_patterns = [p for p in code_patterns if p in text_data.lower()]
            if found_patterns:
                indicators.append(f'Contains potential code patterns: {", ".join(found_patterns)}')
            
            # Look for SQL injection patterns
            sql_patterns = ['union select', 'drop table', 'insert into', 'delete from']
            found_sql = [p for p in sql_patterns if p in text_data.lower()]
            if found_sql:
                indicators.append(f'Contains SQL patterns: {", ".join(found_sql)}')
        
        return {
            'indicator_count': len(indicators),
            'indicators': indicators,
            'risk_level': 'high' if len(indicators) > 3 else 'medium' if len(indicators) > 1 else 'low'
        }
    
    def get_analysis_summary(self, analysis_result: Dict[str, Any]) -> str:
        """
        Generate a human-readable summary of the analysis.
        
        Args:
            analysis_result: Result from analyze_content()
            
        Returns:
            Human-readable summary string
        """
        if analysis_result.get('analysis_skipped'):
            return f"Analysis skipped: {analysis_result['reason']}"
        
        if 'error' in analysis_result:
            return f"Analysis failed: {analysis_result['error']}"
        
        summary_parts = []
        
        # File info
        size_mb = analysis_result['file_size'] / (1024 * 1024)
        summary_parts.append(f"File size: {size_mb:.2f} MB")
        
        # Entropy
        if 'entropy' in analysis_result:
            entropy = analysis_result['entropy']
            summary_parts.append(f"Entropy: {entropy['entropy']:.2f}/8.0 ({entropy['quality']})")
        
        # Binary analysis
        if 'binary_analysis' in analysis_result:
            binary = analysis_result['binary_analysis']
            if binary['is_likely_binary']:
                summary_parts.append("Type: Binary data")
            else:
                summary_parts.append("Type: Text data")
        
        # Security indicators
        if 'security_indicators' in analysis_result:
            security = analysis_result['security_indicators']
            if security['indicator_count'] > 0:
                summary_parts.append(f"Security risk: {security['risk_level']} ({security['indicator_count']} indicators)")
        
        # Embedded files
        if 'embedded_analysis' in analysis_result:
            embedded = analysis_result['embedded_analysis']
            if embedded['embedded_files_found'] > 0:
                summary_parts.append(f"Embedded files: {embedded['embedded_files_found']} found")
        
        return " | ".join(summary_parts)

    def get_basic_info(self, file_path: Path) -> Dict[str, Any]:
        """
        Get basic file information without full analysis.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Dictionary with basic file information
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        try:
            stat = file_path.stat()
            
            # Basic file statistics
            basic_info = {
                'file_size': stat.st_size,
                'creation_time': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modification_time': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'access_time': datetime.fromtimestamp(stat.st_atime).isoformat(),
                'is_executable': os.access(file_path, os.X_OK),
                'permissions': oct(stat.st_mode)[-3:],
            }
            
            # Try to get basic content info for small files
            if stat.st_size < 1024 * 1024:  # 1MB limit for basic info
                try:
                    with open(file_path, 'rb') as f:
                        sample = f.read(1024)  # Read first 1KB
                    
                    # Basic entropy calculation on sample
                    if sample:
                        basic_info['sample_entropy'] = self._calculate_entropy(sample)
                        basic_info['is_likely_text'] = all(32 <= b <= 126 or b in [9, 10, 13] for b in sample[:100])
                    
                except Exception:
                    pass  # Ignore errors for basic info
            
            return basic_info
            
        except Exception as e:
            return {'error': f"Failed to get basic info: {e}"}
