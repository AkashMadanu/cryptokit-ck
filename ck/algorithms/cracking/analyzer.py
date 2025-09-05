"""
Hash strength analysis for CryptoKit (CK)

Simple hash strength and entropy analysis tools for security assessment.
"""

import math
import re
from typing import Dict, Any, List
from collections import Counter


class HashAnalyzer:
    """
    Hash strength and security analyzer.
    
    Provides entropy analysis, pattern detection, and security assessments.
    """
    
    # Security ratings for different hash algorithms
    ALGORITHM_SECURITY = {
        'md5': {
            'rating': 'WEAK',
            'score': 2,
            'description': 'MD5 is cryptographically broken and should not be used for security',
            'vulnerabilities': ['Collision attacks', 'Pre-image attacks', 'Length extension']
        },
        'sha1': {
            'rating': 'WEAK', 
            'score': 3,
            'description': 'SHA-1 is deprecated due to collision vulnerabilities',
            'vulnerabilities': ['Collision attacks', 'Shattered attack']
        },
        'sha256': {
            'rating': 'STRONG',
            'score': 8,
            'description': 'SHA-256 is currently secure and widely recommended',
            'vulnerabilities': ['Length extension (mitigated in HMAC)']
        },
        'sha384': {
            'rating': 'STRONG',
            'score': 9,
            'description': 'SHA-384 provides high security with larger output',
            'vulnerabilities': ['Length extension (mitigated in HMAC)']
        },
        'sha512': {
            'rating': 'STRONG',
            'score': 9,
            'description': 'SHA-512 provides high security with largest output',
            'vulnerabilities': ['Length extension (mitigated in HMAC)']
        },
        'blake2b': {
            'rating': 'STRONG',
            'score': 9,
            'description': 'Blake2b is modern, fast, and secure',
            'vulnerabilities': ['None known']
        },
        'blake2s': {
            'rating': 'STRONG',
            'score': 8,
            'description': 'Blake2s is modern, fast, and secure',
            'vulnerabilities': ['None known']
        }
    }
    
    def analyze_hash_strength(self, hash_value: str, hash_type: str) -> Dict[str, Any]:
        """
        Analyze the strength and security of a hash.
        
        Args:
            hash_value: Hash value to analyze
            hash_type: Type of hash algorithm
            
        Returns:
            Dictionary containing strength analysis
        """
        # Get algorithm security info
        algo_info = self.ALGORITHM_SECURITY.get(hash_type.lower(), {
            'rating': 'UNKNOWN',
            'score': 0,
            'description': 'Unknown hash algorithm',
            'vulnerabilities': ['Unknown']
        })
        
        # Calculate entropy
        entropy = self._calculate_entropy(hash_value)
        
        # Analyze patterns
        pattern_analysis = self._analyze_patterns(hash_value)
        
        # Determine overall security level
        overall_rating = self._determine_overall_rating(algo_info['score'], entropy, pattern_analysis)
        
        # Estimate crack difficulty
        crack_difficulty = self._estimate_crack_difficulty(hash_type, hash_value)
        
        return {
            'hash_value': hash_value,
            'hash_type': hash_type.upper(),
            'algorithm_security': {
                'rating': algo_info['rating'],
                'score': algo_info['score'],
                'description': algo_info['description'],
                'vulnerabilities': algo_info['vulnerabilities']
            },
            'entropy_analysis': {
                'entropy': entropy,
                'max_entropy': math.log2(16) * len(hash_value),  # Hex chars
                'entropy_ratio': entropy / (math.log2(16) * len(hash_value)) if hash_value else 0,
                'quality': self._entropy_quality(entropy, len(hash_value))
            },
            'pattern_analysis': pattern_analysis,
            'overall_rating': overall_rating,
            'crack_difficulty': crack_difficulty,
            'recommendations': self._generate_recommendations(hash_type, overall_rating)
        }
    
    def _calculate_entropy(self, hash_value: str) -> float:
        """
        Calculate Shannon entropy of the hash value.
        
        Args:
            hash_value: Hash string to analyze
            
        Returns:
            Entropy value in bits
        """
        if not hash_value:
            return 0.0
        
        # Count frequency of each character
        char_counts = Counter(hash_value.lower())
        total_chars = len(hash_value)
        
        # Calculate Shannon entropy
        entropy = 0.0
        for count in char_counts.values():
            probability = count / total_chars
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _analyze_patterns(self, hash_value: str) -> Dict[str, Any]:
        """
        Analyze patterns in the hash value.
        
        Args:
            hash_value: Hash string to analyze
            
        Returns:
            Dictionary with pattern analysis
        """
        if not hash_value:
            return {}
        
        # Character distribution analysis
        digits = sum(1 for c in hash_value if c.isdigit())
        letters = sum(1 for c in hash_value if c.isalpha())
        
        # Repetition analysis
        consecutive_repeats = self._find_consecutive_repeats(hash_value)
        
        # Pattern detection
        patterns = []
        
        # Check for obvious patterns
        if re.search(r'(.)\1{3,}', hash_value):
            patterns.append('Excessive character repetition detected')
        
        if re.search(r'(0123|1234|abcd)', hash_value.lower()):
            patterns.append('Sequential character patterns detected')
        
        if hash_value.lower() == '0' * len(hash_value):
            patterns.append('All zeros - likely null/empty input')
        
        if len(set(hash_value.lower())) < len(hash_value) * 0.5:
            patterns.append('Low character diversity')
        
        return {
            'character_distribution': {
                'digits': digits,
                'letters': letters,
                'total_chars': len(hash_value),
                'digit_ratio': digits / len(hash_value) if hash_value else 0,
                'letter_ratio': letters / len(hash_value) if hash_value else 0
            },
            'consecutive_repeats': consecutive_repeats,
            'suspicious_patterns': patterns,
            'character_diversity': len(set(hash_value.lower())) / len(hash_value) if hash_value else 0
        }
    
    def _find_consecutive_repeats(self, hash_value: str) -> List[Dict[str, Any]]:
        """
        Find consecutive character repetitions.
        
        Args:
            hash_value: Hash string to analyze
            
        Returns:
            List of repetition information
        """
        repeats = []
        current_char = ''
        current_count = 0
        
        for char in hash_value:
            if char == current_char:
                current_count += 1
            else:
                if current_count >= 3:  # Report 3+ consecutive chars
                    repeats.append({
                        'character': current_char,
                        'count': current_count,
                        'severity': 'high' if current_count >= 5 else 'medium'
                    })
                current_char = char
                current_count = 1
        
        # Check final sequence
        if current_count >= 3:
            repeats.append({
                'character': current_char,
                'count': current_count,
                'severity': 'high' if current_count >= 5 else 'medium'
            })
        
        return repeats
    
    def _entropy_quality(self, entropy: float, length: int) -> str:
        """
        Determine entropy quality rating.
        
        Args:
            entropy: Calculated entropy
            length: Hash length
            
        Returns:
            Quality rating string
        """
        if length == 0:
            return 'INVALID'
        
        max_entropy = math.log2(16) * length  # Max for hex
        ratio = entropy / max_entropy
        
        if ratio >= 0.95:
            return 'EXCELLENT'
        elif ratio >= 0.85:
            return 'GOOD'
        elif ratio >= 0.70:
            return 'FAIR'
        else:
            return 'POOR'
    
    def _determine_overall_rating(self, algo_score: int, entropy: float, pattern_analysis: Dict) -> Dict[str, Any]:
        """
        Determine overall security rating.
        
        Args:
            algo_score: Algorithm security score
            entropy: Calculated entropy
            pattern_analysis: Pattern analysis results
            
        Returns:
            Overall rating information
        """
        # Start with algorithm score
        base_score = algo_score
        
        # Penalize for poor entropy
        entropy_quality = pattern_analysis.get('character_diversity', 1.0)
        if entropy_quality < 0.7:
            base_score -= 2
        
        # Penalize for suspicious patterns
        if pattern_analysis.get('suspicious_patterns'):
            base_score -= 1
        
        # Penalize for excessive repetition
        repeats = pattern_analysis.get('consecutive_repeats', [])
        if any(r['severity'] == 'high' for r in repeats):
            base_score -= 2
        elif repeats:
            base_score -= 1
        
        # Normalize score
        final_score = max(0, min(10, base_score))
        
        # Determine rating
        if final_score >= 8:
            rating = 'STRONG'
        elif final_score >= 6:
            rating = 'MODERATE'
        elif final_score >= 4:
            rating = 'WEAK'
        else:
            rating = 'VERY_WEAK'
        
        return {
            'rating': rating,
            'score': final_score,
            'max_score': 10
        }
    
    def _estimate_crack_difficulty(self, hash_type: str, hash_value: str) -> Dict[str, Any]:
        """
        Estimate the difficulty of cracking this hash.
        
        Args:
            hash_type: Type of hash algorithm
            hash_value: Hash value
            
        Returns:
            Crack difficulty estimation
        """
        algo_info = self.ALGORITHM_SECURITY.get(hash_type.lower(), {})
        
        # Base difficulty by algorithm
        if hash_type.lower() in ['md5', 'sha1']:
            base_difficulty = 'LOW'
            time_estimate = 'Minutes to hours'
        elif hash_type.lower() in ['sha256', 'blake2s']:
            base_difficulty = 'MEDIUM'
            time_estimate = 'Hours to days'
        else:  # sha384, sha512, blake2b
            base_difficulty = 'HIGH'
            time_estimate = 'Days to years'
        
        return {
            'difficulty': base_difficulty,
            'time_estimate': time_estimate,
            'factors': [
                f"Algorithm: {hash_type.upper()}",
                f"Hash length: {len(hash_value)} characters",
                "Password complexity unknown",
                "Assumes standard hardware"
            ]
        }
    
    def _generate_recommendations(self, hash_type: str, overall_rating: Dict) -> List[str]:
        """
        Generate security recommendations.
        
        Args:
            hash_type: Type of hash algorithm
            overall_rating: Overall security rating
            
        Returns:
            List of recommendations
        """
        recommendations = []
        
        # Algorithm-specific recommendations
        if hash_type.lower() in ['md5', 'sha1']:
            recommendations.append(f"⚠️  Upgrade from {hash_type.upper()} to SHA-256 or higher")
            recommendations.append("🔒 Use salted hashing for password storage")
        
        # Rating-based recommendations
        if overall_rating['rating'] in ['WEAK', 'VERY_WEAK']:
            recommendations.append("🚨 This hash shows signs of weak input or algorithm")
            recommendations.append("🔐 Consider using stronger hash algorithms")
        
        # General recommendations
        recommendations.extend([
            "🧂 Always use salt for password hashing",
            "🔄 Consider key derivation functions (PBKDF2, Argon2) for passwords",
            "📊 Regular security audits recommended"
        ])
        
        return recommendations
    
    def compare_algorithms(self) -> Dict[str, Any]:
        """
        Compare security of different hash algorithms.
        
        Returns:
            Comparison of supported algorithms
        """
        return {
            'algorithms': self.ALGORITHM_SECURITY,
            'recommendations': {
                'strongest': ['sha512', 'blake2b', 'sha384'],
                'recommended': ['sha256', 'blake2s'],
                'deprecated': ['md5', 'sha1']
            },
            'use_cases': {
                'password_storage': 'Use PBKDF2/Argon2 instead of plain hashing',
                'file_integrity': 'SHA-256 or higher recommended',
                'digital_signatures': 'SHA-256 or SHA-512',
                'performance_critical': 'Blake2b/Blake2s for speed'
            }
        }
