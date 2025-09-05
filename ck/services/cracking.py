"""
Hash cracking service for CryptoKit (CK)

High-level service that combines hash detection, dictionary attacks,
and strength analysis for comprehensive hash cracking capabilities.
"""

import logging
from typing import Optional, Dict, Any, List
from pathlib import Path

from ..algorithms.cracking.detector import HashDetector
from ..algorithms.cracking.dictionary import DictionaryAttack
from ..algorithms.cracking.analyzer import HashAnalyzer
from ..core.exceptions import CrackingError


class CrackingService:
    """
    High-level hash cracking service.
    
    Provides unified interface for hash detection, cracking attempts,
    and security analysis.
    """
    
    def __init__(self):
        """Initialize the cracking service."""
        self.logger = logging.getLogger(__name__)
        self.detector = HashDetector()
        self.dictionary = DictionaryAttack()
        self.analyzer = HashAnalyzer()
    
    def analyze_hash(self, hash_value: str) -> Dict[str, Any]:
        """
        Perform comprehensive hash analysis.
        
        Args:
            hash_value: Hash string to analyze
            
        Returns:
            Complete analysis results
        """
        try:
            # Detect hash type
            detection_results = self.detector.detect_hash_type(hash_value)
            most_likely_type = self.detector.get_most_likely_type(hash_value)
            
            if not most_likely_type:
                raise CrackingError("Unable to detect hash type")
            
            # Perform strength analysis
            strength_analysis = self.analyzer.analyze_hash_strength(
                hash_value, most_likely_type.hash_type
            )
            
            # Compile results
            return {
                'hash_value': hash_value,
                'detection': {
                    'most_likely': {
                        'type': most_likely_type.hash_type,
                        'description': most_likely_type.description,
                        'confidence': most_likely_type.confidence,
                        'bit_length': most_likely_type.bit_length
                    },
                    'all_matches': [
                        {
                            'type': match.hash_type,
                            'description': match.description,
                            'confidence': match.confidence,
                            'bit_length': match.bit_length
                        }
                        for match in detection_results
                    ]
                },
                'strength_analysis': strength_analysis,
                'supported_operations': {
                    'can_crack': True,
                    'can_analyze': True,
                    'dictionary_attack': True,
                    'brute_force': True
                }
            }
            
        except Exception as e:
            self.logger.error(f"Hash analysis failed: {e}")
            raise CrackingError(f"Hash analysis failed: {e}")
    
    def attempt_crack(self, 
                     hash_value: str,
                     hash_type: Optional[str] = None,
                     wordlist_file: Optional[str] = None,
                     max_brute_length: int = 6,
                     quick_mode: bool = False) -> Dict[str, Any]:
        """
        Attempt to crack a hash using available methods.
        
        Args:
            hash_value: Hash to crack
            hash_type: Hash type (auto-detect if None)
            wordlist_file: Custom wordlist file path
            max_brute_length: Maximum length for brute force
            quick_mode: Use only common passwords
            
        Returns:
            Cracking attempt results
        """
        try:
            # Auto-detect hash type if not provided
            if not hash_type:
                most_likely = self.detector.get_most_likely_type(hash_value)
                if not most_likely:
                    raise CrackingError("Cannot detect hash type")
                hash_type = most_likely.hash_type
                self.logger.info(f"Auto-detected hash type: {hash_type}")
            
            # Prepare wordlist
            wordlist = None
            if wordlist_file:
                wordlist = self.dictionary.load_wordlist_file(wordlist_file)
                self.logger.info(f"Loaded {len(wordlist)} passwords from wordlist")
            elif quick_mode:
                # Use only a subset of common passwords for quick mode
                wordlist = self.dictionary.COMMON_PASSWORDS[:20]
                self.logger.info("Using quick mode with top 20 common passwords")
            
            # Adjust brute force length based on mode
            if quick_mode:
                max_brute_length = min(4, max_brute_length)
            
            self.logger.info(f"Starting crack attempt for {hash_type} hash")
            
            # Attempt cracking
            result = self.dictionary.crack_hash(
                target_hash=hash_value,
                hash_type=hash_type,
                wordlist=wordlist,
                max_length=max_brute_length
            )
            
            if result:
                self.logger.info(f"Hash cracked successfully using {result['method']}")
                return {
                    'success': True,
                    'result': result,
                    'message': f"Password found: {result['password']}",
                    'method_used': result['method'],
                    'hash_type': hash_type
                }
            else:
                self.logger.info("Hash cracking failed - password not found")
                return {
                    'success': False,
                    'result': None,
                    'message': "Password not found with current methods",
                    'hash_type': hash_type,
                    'suggestions': [
                        "Try a larger wordlist",
                        f"Increase brute force length (current: {max_brute_length})",
                        "Consider the password may be longer or more complex"
                    ]
                }
                
        except Exception as e:
            self.logger.error(f"Crack attempt failed: {e}")
            raise CrackingError(f"Crack attempt failed: {e}")
    
    def quick_crack(self, hash_value: str) -> Dict[str, Any]:
        """
        Quick crack attempt using common passwords only.
        
        Args:
            hash_value: Hash to crack
            
        Returns:
            Quick crack results
        """
        return self.attempt_crack(
            hash_value=hash_value,
            quick_mode=True
        )
    
    def get_crack_stats(self) -> Dict[str, Any]:
        """
        Get statistics about cracking capabilities.
        
        Returns:
            Cracking capability statistics
        """
        wordlist_info = self.dictionary.get_wordlist_info()
        
        return {
            'supported_algorithms': list(self.dictionary.hash_algorithms.keys()),
            'detection_capabilities': {
                'supported_types': self.detector.get_supported_types(),
                'pattern_matching': True,
                'confidence_scoring': True
            },
            'attack_methods': {
                'dictionary_attack': {
                    'enabled': True,
                    'built_in_wordlist': wordlist_info,
                    'custom_wordlist_support': True
                },
                'brute_force': {
                    'enabled': True,
                    'max_recommended_length': 6,
                    'character_sets': ['digits', 'lowercase', 'uppercase', 'alphanumeric']
                }
            },
            'analysis_features': {
                'entropy_calculation': True,
                'pattern_detection': True,
                'strength_assessment': True,
                'security_recommendations': True
            }
        }
    
    def detect_only(self, hash_value: str) -> Dict[str, Any]:
        """
        Only detect hash type without cracking attempt.
        
        Args:
            hash_value: Hash to analyze
            
        Returns:
            Detection results only
        """
        try:
            detection_results = self.detector.detect_hash_type(hash_value)
            most_likely = self.detector.get_most_likely_type(hash_value)
            
            return {
                'hash_value': hash_value,
                'most_likely_type': most_likely.hash_type if most_likely else None,
                'confidence': most_likely.confidence if most_likely else 0,
                'description': most_likely.description if most_likely else "Unknown",
                'all_possibilities': [
                    {
                        'type': match.hash_type,
                        'confidence': match.confidence,
                        'description': match.description
                    }
                    for match in detection_results
                ],
                'is_valid_hash': len(detection_results) > 0
            }
            
        except Exception as e:
            self.logger.error(f"Hash detection failed: {e}")
            raise CrackingError(f"Hash detection failed: {e}")
