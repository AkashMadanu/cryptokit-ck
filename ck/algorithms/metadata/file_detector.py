"""
File type detection for CryptoKit (CK)

Advanced file type detection using magic numbers, MIME types,
and content analysis.
"""

import os
import mimetypes
from pathlib import Path
from typing import Dict, Any, Optional, List
import struct


class FileTypeDetector:
    """
    Advanced file type detector using multiple detection methods.
    
    Combines magic number analysis, MIME type detection, and
    content analysis for accurate file type identification.
    """
    
    # Common file magic numbers
    MAGIC_NUMBERS = {
        # Images
        b'\xFF\xD8\xFF': {'type': 'JPEG', 'mime': 'image/jpeg', 'ext': ['.jpg', '.jpeg']},
        b'\x89PNG\r\n\x1a\n': {'type': 'PNG', 'mime': 'image/png', 'ext': ['.png']},
        b'GIF87a': {'type': 'GIF', 'mime': 'image/gif', 'ext': ['.gif']},
        b'GIF89a': {'type': 'GIF', 'mime': 'image/gif', 'ext': ['.gif']},
        b'BM': {'type': 'BMP', 'mime': 'image/bmp', 'ext': ['.bmp']},
        b'RIFF': {'type': 'WEBP', 'mime': 'image/webp', 'ext': ['.webp']},  # Needs WEBP verification
        
        # Documents
        b'%PDF': {'type': 'PDF', 'mime': 'application/pdf', 'ext': ['.pdf']},
        b'PK\x03\x04': {'type': 'ZIP', 'mime': 'application/zip', 'ext': ['.zip', '.docx', '.xlsx', '.pptx']},
        b'\xD0\xCF\x11\xE0': {'type': 'MS_OFFICE', 'mime': 'application/vnd.ms-office', 'ext': ['.doc', '.xls', '.ppt']},
        
        # Archives
        b'7z\xBC\xAF\x27\x1C': {'type': '7Z', 'mime': 'application/x-7z-compressed', 'ext': ['.7z']},
        b'\x1f\x8b': {'type': 'GZIP', 'mime': 'application/gzip', 'ext': ['.gz']},
        b'Rar!\x1a\x07\x00': {'type': 'RAR', 'mime': 'application/x-rar-compressed', 'ext': ['.rar']},
        
        # Executables
        b'MZ': {'type': 'PE_EXECUTABLE', 'mime': 'application/x-msdownload', 'ext': ['.exe', '.dll']},
        b'\x7fELF': {'type': 'ELF_EXECUTABLE', 'mime': 'application/x-executable', 'ext': ['']},
        
        # Media
        b'ID3': {'type': 'MP3', 'mime': 'audio/mpeg', 'ext': ['.mp3']},
        b'\x00\x00\x00\x18ftypmp4': {'type': 'MP4', 'mime': 'video/mp4', 'ext': ['.mp4']},
        b'\x00\x00\x00\x20ftypM4A': {'type': 'M4A', 'mime': 'audio/mp4', 'ext': ['.m4a']},
        
        # Text/Data
        b'#!/': {'type': 'SCRIPT', 'mime': 'text/x-shellscript', 'ext': ['.sh', '.py', '.pl']},
        b'<?xml': {'type': 'XML', 'mime': 'application/xml', 'ext': ['.xml']},
        b'{\n': {'type': 'JSON', 'mime': 'application/json', 'ext': ['.json']},
    }
    
    def detect_file_type(self, file_path: Path) -> Dict[str, Any]:
        """
        Perform comprehensive file type detection.
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Dictionary with detection results
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Initialize result
        result = {
            'file_path': str(file_path),
            'file_name': file_path.name,
            'file_size': file_path.stat().st_size,
            'extension': file_path.suffix.lower(),
            'detection_methods': {}
        }
        
        # Method 1: Magic number detection
        magic_result = self._detect_by_magic(file_path)
        result['detection_methods']['magic_number'] = magic_result
        
        # Method 2: MIME type detection
        mime_result = self._detect_by_mime(file_path)
        result['detection_methods']['mime_type'] = mime_result
        
        # Method 3: Extension analysis
        ext_result = self._detect_by_extension(file_path)
        result['detection_methods']['extension'] = ext_result
        
        # Method 4: Content analysis for text files
        if file_path.stat().st_size < 1024 * 1024:  # Only for files < 1MB
            content_result = self._detect_by_content(file_path)
            result['detection_methods']['content_analysis'] = content_result
        
        # Determine final file type
        final_type = self._determine_final_type(result['detection_methods'])
        result['detected_type'] = final_type
        
        # Calculate confidence score
        result['confidence'] = self._calculate_confidence(result['detection_methods'], final_type)
        
        return result
    
    def _detect_by_magic(self, file_path: Path) -> Dict[str, Any]:
        """Detect file type using magic numbers."""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(32)  # Read first 32 bytes
            
            # Check each magic number
            for magic_bytes, info in self.MAGIC_NUMBERS.items():
                if header.startswith(magic_bytes):
                    return {
                        'method': 'magic_number',
                        'detected': True,
                        'type': info['type'],
                        'mime': info['mime'],
                        'possible_extensions': info['ext'],
                        'magic_bytes': magic_bytes.hex(),
                        'confidence': 0.9
                    }
            
            # Special case for WEBP (needs additional verification)
            if header.startswith(b'RIFF') and b'WEBP' in header[:12]:
                return {
                    'method': 'magic_number',
                    'detected': True,
                    'type': 'WEBP',
                    'mime': 'image/webp',
                    'possible_extensions': ['.webp'],
                    'magic_bytes': header[:12].hex(),
                    'confidence': 0.9
                }
            
            return {
                'method': 'magic_number',
                'detected': False,
                'reason': 'No known magic number found',
                'header_bytes': header[:16].hex()
            }
            
        except Exception as e:
            return {
                'method': 'magic_number',
                'detected': False,
                'error': str(e)
            }
    
    def _detect_by_mime(self, file_path: Path) -> Dict[str, Any]:
        """Detect file type using MIME type detection."""
        try:
            mime_type, encoding = mimetypes.guess_type(str(file_path))
            
            if mime_type:
                return {
                    'method': 'mime_type',
                    'detected': True,
                    'mime_type': mime_type,
                    'encoding': encoding,
                    'confidence': 0.7
                }
            else:
                return {
                    'method': 'mime_type',
                    'detected': False,
                    'reason': 'MIME type could not be determined'
                }
                
        except Exception as e:
            return {
                'method': 'mime_type',
                'detected': False,
                'error': str(e)
            }
    
    def _detect_by_extension(self, file_path: Path) -> Dict[str, Any]:
        """Analyze file extension."""
        ext = file_path.suffix.lower()
        
        if not ext:
            return {
                'method': 'extension',
                'detected': False,
                'reason': 'No file extension'
            }
        
        # Common extension mappings
        ext_mappings = {
            '.txt': {'type': 'TEXT', 'mime': 'text/plain'},
            '.py': {'type': 'PYTHON', 'mime': 'text/x-python'},
            '.js': {'type': 'JAVASCRIPT', 'mime': 'application/javascript'},
            '.html': {'type': 'HTML', 'mime': 'text/html'},
            '.css': {'type': 'CSS', 'mime': 'text/css'},
            '.json': {'type': 'JSON', 'mime': 'application/json'},
            '.xml': {'type': 'XML', 'mime': 'application/xml'},
            '.csv': {'type': 'CSV', 'mime': 'text/csv'},
        }
        
        if ext in ext_mappings:
            return {
                'method': 'extension',
                'detected': True,
                'extension': ext,
                'type': ext_mappings[ext]['type'],
                'mime': ext_mappings[ext]['mime'],
                'confidence': 0.6
            }
        else:
            return {
                'method': 'extension',
                'detected': True,
                'extension': ext,
                'type': f'UNKNOWN_{ext[1:].upper()}',
                'confidence': 0.3
            }
    
    def _detect_by_content(self, file_path: Path) -> Dict[str, Any]:
        """Analyze file content for text files."""
        try:
            # Try to read as text
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(1024)  # Read first 1KB
            
            # Check for specific content patterns
            if content.strip().startswith('{') and content.strip().endswith('}'):
                return {
                    'method': 'content_analysis',
                    'detected': True,
                    'type': 'JSON',
                    'mime': 'application/json',
                    'confidence': 0.8
                }
            elif content.strip().startswith('<') and content.strip().endswith('>'):
                if '<?xml' in content:
                    return {
                        'method': 'content_analysis',
                        'detected': True,
                        'type': 'XML',
                        'mime': 'application/xml',
                        'confidence': 0.8
                    }
                elif '<html' in content.lower():
                    return {
                        'method': 'content_analysis',
                        'detected': True,
                        'type': 'HTML',
                        'mime': 'text/html',
                        'confidence': 0.8
                    }
            elif content.startswith('#!'):
                return {
                    'method': 'content_analysis',
                    'detected': True,
                    'type': 'SCRIPT',
                    'mime': 'text/x-shellscript',
                    'confidence': 0.8
                }
            
            # Check if it's text
            try:
                content.encode('ascii')
                return {
                    'method': 'content_analysis',
                    'detected': True,
                    'type': 'TEXT',
                    'mime': 'text/plain',
                    'confidence': 0.5
                }
            except UnicodeEncodeError:
                return {
                    'method': 'content_analysis',
                    'detected': True,
                    'type': 'TEXT_UNICODE',
                    'mime': 'text/plain',
                    'confidence': 0.5
                }
                
        except Exception:
            # If we can't read as text, it's likely binary
            return {
                'method': 'content_analysis',
                'detected': True,
                'type': 'BINARY',
                'mime': 'application/octet-stream',
                'confidence': 0.6
            }
    
    def _determine_final_type(self, detection_methods: Dict) -> Dict[str, Any]:
        """Determine the final file type based on all detection methods."""
        # Prioritize magic number detection (highest confidence)
        if detection_methods.get('magic_number', {}).get('detected'):
            magic = detection_methods['magic_number']
            return {
                'type': magic['type'],
                'mime': magic['mime'],
                'primary_method': 'magic_number'
            }
        
        # Then MIME type detection
        if detection_methods.get('mime_type', {}).get('detected'):
            mime = detection_methods['mime_type']
            return {
                'type': mime['mime_type'].split('/')[1].upper(),
                'mime': mime['mime_type'],
                'primary_method': 'mime_type'
            }
        
        # Then content analysis
        if detection_methods.get('content_analysis', {}).get('detected'):
            content = detection_methods['content_analysis']
            return {
                'type': content['type'],
                'mime': content['mime'],
                'primary_method': 'content_analysis'
            }
        
        # Finally extension
        if detection_methods.get('extension', {}).get('detected'):
            ext = detection_methods['extension']
            return {
                'type': ext['type'],
                'mime': ext.get('mime', 'application/octet-stream'),
                'primary_method': 'extension'
            }
        
        # Unknown file type
        return {
            'type': 'UNKNOWN',
            'mime': 'application/octet-stream',
            'primary_method': 'none'
        }
    
    def _calculate_confidence(self, detection_methods: Dict, final_type: Dict) -> float:
        """Calculate overall confidence score."""
        confidence_sum = 0.0
        method_count = 0
        
        for method, result in detection_methods.items():
            if isinstance(result, dict) and result.get('detected'):
                confidence_sum += result.get('confidence', 0.5)
                method_count += 1
        
        if method_count == 0:
            return 0.0
        
        return min(1.0, confidence_sum / method_count)
    
    def is_binary_file(self, file_path: Path) -> bool:
        """
        Check if file is binary.
        
        Args:
            file_path: Path to file
            
        Returns:
            True if file appears to be binary
        """
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
            
            # Check for null bytes (common in binary files)
            if b'\x00' in chunk:
                return True
            
            # Check for high ratio of non-printable characters
            printable_chars = sum(1 for b in chunk if 32 <= b <= 126 or b in (9, 10, 13))
            if len(chunk) > 0 and printable_chars / len(chunk) < 0.75:
                return True
            
            return False
            
        except Exception:
            return True  # Assume binary if we can't read it
    
    def get_supported_types(self) -> List[str]:
        """
        Get list of file types that can be detected.
        
        Returns:
            List of supported file type names
        """
        types = set()
        for info in self.MAGIC_NUMBERS.values():
            types.add(info['type'])
        return sorted(list(types))
