"""
Dictionary attack implementation for CryptoKit (CK)

Simple dictionary-based hash cracking using built-in wordlists
and brute force for short passwords.
"""

import hashlib
import itertools
import string
from typing import Optional, List, Dict, Any, Iterator
from pathlib import Path


class DictionaryAttack:
    """
    Simple dictionary attack implementation.
    
    Supports common password lists and basic brute force attacks.
    """
    
    # Built-in common passwords (top 100 most common)
    COMMON_PASSWORDS = [
        "password", "123456", "123456789", "12345678", "12345", "1234567890",
        "qwerty", "abc123", "password1", "admin", "letmein", "welcome",
        "monkey", "dragon", "master", "hello", "login", "pass", "admin123",
        "root", "test", "guest", "user", "demo", "default", "changeme",
        "secret", "football", "baseball", "basketball", "princess", "sunshine",
        "iloveyou", "lovely", "computer", "charlie", "shadow", "batman",
        "superman", "michael", "jordan", "tigger", "summer", "freedom",
        "pepper", "flower", "orange", "purple", "chicken", "matrix",
        "killer", "trustno1", "hunter", "buster", "soccer", "hockey",
        "dallas", "george", "michelle", "jessica", "daniel", "andrew",
        "thomas", "joshua", "amanda", "jennifer", "ashley", "nicole",
        "elizabeth", "heather", "melissa", "stephanie", "kevin", "steven",
        "matthew", "anthony", "joshua", "christopher", "david", "james",
        "robert", "john", "william", "mary", "patricia", "linda", "barbara",
        "margaret", "susan", "dorothy", "lisa", "nancy", "karen", "betty",
        "helen", "sandra", "donna", "carol", "ruth", "sharon", "michelle",
        "laura", "sarah", "kimberly", "deborah", "dorothy", "amy", "angela"
    ]
    
    def __init__(self):
        """Initialize the dictionary attack engine."""
        self.hash_algorithms = {
            'md5': lambda x: hashlib.md5(x.encode()).hexdigest(),
            'sha1': lambda x: hashlib.sha1(x.encode()).hexdigest(),
            'sha256': lambda x: hashlib.sha256(x.encode()).hexdigest(),
            'sha384': lambda x: hashlib.sha384(x.encode()).hexdigest(),
            'sha512': lambda x: hashlib.sha512(x.encode()).hexdigest(),
            'blake2b': lambda x: hashlib.blake2b(x.encode()).hexdigest(),
            'blake2s': lambda x: hashlib.blake2s(x.encode()).hexdigest()
        }
    
    def crack_hash(self, 
                   target_hash: str, 
                   hash_type: str,
                   wordlist: Optional[List[str]] = None,
                   max_length: int = 6) -> Optional[Dict[str, Any]]:
        """
        Attempt to crack a hash using dictionary and brute force methods.
        
        Args:
            target_hash: Hash value to crack
            hash_type: Type of hash (md5, sha1, sha256, etc.)
            wordlist: Custom wordlist (uses built-in if None)
            max_length: Maximum length for brute force attack
            
        Returns:
            Dictionary with crack result or None if not found
        """
        if hash_type not in self.hash_algorithms:
            raise ValueError(f"Unsupported hash type: {hash_type}")
        
        target_hash = target_hash.lower().strip()
        hash_func = self.hash_algorithms[hash_type]
        
        # Try dictionary attack first
        result = self._dictionary_attack(target_hash, hash_func, wordlist)
        if result:
            return {
                'password': result,
                'method': 'dictionary',
                'hash_type': hash_type,
                'target_hash': target_hash
            }
        
        # Try brute force for short passwords
        result = self._brute_force_attack(target_hash, hash_func, max_length)
        if result:
            return {
                'password': result,
                'method': 'brute_force',
                'hash_type': hash_type,
                'target_hash': target_hash
            }
        
        return None
    
    def _dictionary_attack(self, 
                          target_hash: str, 
                          hash_func, 
                          wordlist: Optional[List[str]] = None) -> Optional[str]:
        """
        Perform dictionary attack using wordlist.
        
        Args:
            target_hash: Target hash to crack
            hash_func: Hash function to use
            wordlist: List of passwords to try
            
        Returns:
            Password if found, None otherwise
        """
        if wordlist is None:
            wordlist = self.COMMON_PASSWORDS
        
        for password in wordlist:
            # Try password as-is
            if hash_func(password) == target_hash:
                return password
            
            # Try common variations
            variations = self._generate_variations(password)
            for variation in variations:
                if hash_func(variation) == target_hash:
                    return variation
        
        return None
    
    def _brute_force_attack(self, 
                           target_hash: str, 
                           hash_func, 
                           max_length: int = 6) -> Optional[str]:
        """
        Perform brute force attack for short passwords.
        
        Args:
            target_hash: Target hash to crack
            hash_func: Hash function to use
            max_length: Maximum password length to try
            
        Returns:
            Password if found, None otherwise
        """
        # Character sets for brute force
        charset_digits = string.digits
        charset_lower = string.ascii_lowercase
        charset_upper = string.ascii_uppercase
        charset_symbols = "!@#$%^&*"
        
        # Try different character sets in order of likelihood
        charsets = [
            charset_digits,  # Numbers only
            charset_lower,   # Lowercase only
            charset_lower + charset_digits,  # Lowercase + digits
            charset_lower + charset_upper,   # Letters only
            charset_lower + charset_upper + charset_digits,  # Alphanumeric
        ]
        
        for charset in charsets:
            for length in range(1, min(max_length + 1, 7)):  # Limit to 6 chars max
                for password_tuple in itertools.product(charset, repeat=length):
                    password = ''.join(password_tuple)
                    if hash_func(password) == target_hash:
                        return password
        
        return None
    
    def _generate_variations(self, password: str) -> List[str]:
        """
        Generate common password variations.
        
        Args:
            password: Base password
            
        Returns:
            List of password variations
        """
        variations = []
        
        # Capitalization variations
        variations.extend([
            password.upper(),
            password.capitalize(),
            password.lower()
        ])
        
        # Number suffixes (common years and simple numbers)
        common_suffixes = ['1', '12', '123', '1234', '2023', '2024', '2025']
        for suffix in common_suffixes:
            variations.extend([
                password + suffix,
                password.capitalize() + suffix
            ])
        
        # Common symbol suffixes
        symbol_suffixes = ['!', '!!', '@', '#', '$']
        for suffix in symbol_suffixes:
            variations.extend([
                password + suffix,
                password.capitalize() + suffix
            ])
        
        # Leet speak substitutions (basic)
        leet_password = password.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0')
        if leet_password != password:
            variations.append(leet_password)
            variations.append(leet_password.capitalize())
        
        return list(set(variations))  # Remove duplicates
    
    def load_wordlist_file(self, filepath: str) -> List[str]:
        """
        Load passwords from a wordlist file.
        
        Args:
            filepath: Path to wordlist file
            
        Returns:
            List of passwords from file
        """
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            return wordlist
        except Exception as e:
            raise IOError(f"Error loading wordlist file: {e}")
    
    def estimate_time(self, hash_type: str, attack_mode: str, **kwargs) -> str:
        """
        Provide a simple time estimate for cracking attempts.
        
        Args:
            hash_type: Type of hash
            attack_mode: Attack mode ('dictionary' or 'brute_force')
            **kwargs: Additional parameters
            
        Returns:
            Human-readable time estimate
        """
        if attack_mode == 'dictionary':
            # Dictionary attacks are usually very fast
            return "< 1 minute"
        
        elif attack_mode == 'brute_force':
            max_length = kwargs.get('max_length', 6)
            
            if max_length <= 4:
                return "< 5 minutes"
            elif max_length <= 6:
                return "< 30 minutes"
            else:
                return "> 1 hour"
        
        return "Unknown"
    
    def get_wordlist_info(self) -> Dict[str, Any]:
        """
        Get information about the built-in wordlist.
        
        Returns:
            Dictionary with wordlist information
        """
        return {
            'name': 'Built-in Common Passwords',
            'size': len(self.COMMON_PASSWORDS),
            'description': 'Top 100 most common passwords',
            'source': 'Common password databases'
        }
