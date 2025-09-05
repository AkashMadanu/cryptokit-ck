"""
File metadata service for CryptoKit (CK)

Service layer for file metadata analysis, type detection,
content analysis, and security scanning.
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional

from .file_detector import FileTypeDetector
from .content_analyzer import ContentAnalyzer  
from .security_scanner import SecurityScanner


class MetadataService:
    """
    Service for comprehensive file metadata analysis.
    
    Provides unified interface for file type detection, content analysis,
    and security scanning capabilities.
    """
    
    def __init__(self):
        """Initialize the metadata service."""
        self.file_detector = FileTypeDetector()
        self.content_analyzer = ContentAnalyzer()
        self.security_scanner = SecurityScanner()
        
        # Import logger here to avoid circular imports
        from ck.core.logger import get_logger
        self.logger = get_logger(__name__)
    
    def get_name(self) -> str:
        """Return algorithm name."""
        return "metadata_analysis"
    
    def get_description(self) -> str:
        """Return algorithm description."""
        return "Comprehensive file metadata analysis including type detection, content analysis, and security scanning"
    
    def get_capabilities(self) -> List[str]:
        """Return list of capabilities."""
        return [
            "file_type_detection",
            "content_analysis", 
            "security_scanning",
            "metadata_extraction",
            "risk_assessment"
        ]
    
    def analyze_file(self, file_path: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform comprehensive file analysis.
        
        Args:
            file_path: Path to file to analyze
            options: Analysis options
                - include_content: Include content analysis (default: True)
                - include_security: Include security scan (default: True)
                - max_file_size: Maximum file size to analyze in bytes (default: 100MB)
                - output_format: Output format ('json', 'summary', 'detailed') (default: 'json')
        
        Returns:
            Dictionary containing analysis results
        """
        if options is None:
            options = {}
        
        # Default options
        include_content = options.get('include_content', True)
        include_security = options.get('include_security', True)
        max_file_size = options.get('max_file_size', 100 * 1024 * 1024)  # 100MB
        output_format = options.get('output_format', 'json')
        
        file_path_obj = Path(file_path)
        
        if not file_path_obj.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Check file size
        file_size = file_path_obj.stat().st_size
        if file_size > max_file_size:
            raise ValueError(f"File too large: {file_size} bytes (max: {max_file_size})")
        
        result = {
            'file_path': str(file_path_obj.absolute()),
            'analysis_timestamp': None,  # Will be set by each component
            'analysis_options': options
        }
        
        try:
            # 1. File type detection
            self.logger.info(f"Detecting file type for: {file_path}")
            result['file_type'] = self.file_detector.detect_file_type(file_path_obj)
            
            # 2. Content analysis (if requested)
            if include_content:
                self.logger.info(f"Analyzing content for: {file_path}")
                result['content_analysis'] = self.content_analyzer.analyze_content(file_path_obj)
            
            # 3. Security scanning (if requested)
            if include_security:
                self.logger.info(f"Security scanning: {file_path}")
                result['security_scan'] = self.security_scanner.scan_file(file_path_obj)
            
            # 4. Generate summary
            result['summary'] = self._generate_summary(result)
            
            # Format output
            if output_format == 'summary':
                return self._format_summary(result)
            elif output_format == 'detailed':
                return self._format_detailed(result)
            else:
                return result
                
        except Exception as e:
            self.logger.error(f"Analysis failed for {file_path}: {e}")
            result['error'] = str(e)
            return result
    
    def analyze_directory(self, directory_path: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze all files in a directory.
        
        Args:
            directory_path: Path to directory to analyze
            options: Analysis options (same as analyze_file plus):
                - recursive: Analyze subdirectories recursively (default: False)
                - file_pattern: Pattern to match files (default: '*')
                - max_files: Maximum number of files to analyze (default: 100)
        
        Returns:
            Dictionary containing analysis results for all files
        """
        if options is None:
            options = {}
        
        recursive = options.get('recursive', False)
        file_pattern = options.get('file_pattern', '*')
        max_files = options.get('max_files', 100)
        
        directory_path_obj = Path(directory_path)
        
        if not directory_path_obj.exists():
            raise FileNotFoundError(f"Directory not found: {directory_path}")
        
        if not directory_path_obj.is_dir():
            raise ValueError(f"Path is not a directory: {directory_path}")
        
        # Find files to analyze
        if recursive:
            files = list(directory_path_obj.rglob(file_pattern))
        else:
            files = list(directory_path_obj.glob(file_pattern))
        
        # Filter to regular files only
        files = [f for f in files if f.is_file()]
        
        if len(files) > max_files:
            self.logger.warning(f"Found {len(files)} files, limiting to {max_files}")
            files = files[:max_files]
        
        result = {
            'directory_path': str(directory_path_obj.absolute()),
            'analysis_options': options,
            'total_files_found': len(files),
            'files_analyzed': 0,
            'files': {},
            'summary': {}
        }
        
        # Analyze each file
        for file_path in files:
            try:
                self.logger.info(f"Analyzing file {result['files_analyzed'] + 1}/{len(files)}: {file_path.name}")
                file_result = self.analyze_file(str(file_path), options)
                result['files'][str(file_path.relative_to(directory_path_obj))] = file_result
                result['files_analyzed'] += 1
            except Exception as e:
                self.logger.error(f"Failed to analyze {file_path}: {e}")
                result['files'][str(file_path.relative_to(directory_path_obj))] = {'error': str(e)}
        
        # Generate directory summary
        result['summary'] = self._generate_directory_summary(result)
        
        return result
    
    def get_file_metadata(self, file_path: str) -> Dict[str, Any]:
        """
        Get basic file metadata without full analysis.
        
        Args:
            file_path: Path to file
            
        Returns:
            Dictionary with basic metadata
        """
        file_path_obj = Path(file_path)
        
        if not file_path_obj.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Just do file type detection and basic content info
        result = {
            'file_path': str(file_path_obj.absolute()),
            'file_type': self.file_detector.detect_file_type(file_path_obj),
            'basic_info': self.content_analyzer.get_basic_info(file_path_obj)
        }
        
        return result
    
    def _generate_summary(self, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of analysis results."""
        summary = {
            'file_info': {},
            'key_findings': [],
            'risk_assessment': 'unknown',
            'recommendations': []
        }
        
        # File type summary
        if 'file_type' in analysis_result:
            file_type = analysis_result['file_type']
            summary['file_info'] = {
                'detected_type': file_type.get('detected_type', 'unknown'),
                'confidence': file_type.get('confidence', 0),
                'file_size': file_type.get('file_size', 0)
            }
        
        # Content analysis summary
        if 'content_analysis' in analysis_result:
            content = analysis_result['content_analysis']
            
            if 'entropy_analysis' in content:
                entropy = content['entropy_analysis']['overall_entropy']
                if entropy > 7.5:
                    summary['key_findings'].append(f"High entropy content ({entropy:.2f})")
                elif entropy < 3.0:
                    summary['key_findings'].append(f"Low entropy content ({entropy:.2f})")
            
            if 'embedded_files' in content and content['embedded_files']['files_found'] > 0:
                count = content['embedded_files']['files_found']
                summary['key_findings'].append(f"Contains {count} embedded files")
            
            if 'strings_analysis' in content:
                strings_count = content['strings_analysis']['total_strings']
                if strings_count > 1000:
                    summary['key_findings'].append(f"Large number of strings ({strings_count})")
        
        # Security scan summary
        if 'security_scan' in analysis_result:
            security = analysis_result['security_scan']
            
            if 'risk_assessment' in security:
                risk = security['risk_assessment']
                summary['risk_assessment'] = risk['risk_level'].lower()
                
                if risk['risk_factors']:
                    summary['key_findings'].extend(risk['risk_factors'][:3])  # Top 3
                
                summary['recommendations'].append(risk['recommendation'])
        
        return summary
    
    def _generate_directory_summary(self, directory_result: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary for directory analysis."""
        files = directory_result.get('files', {})
        
        summary = {
            'total_files': len(files),
            'file_types': {},
            'risk_levels': {},
            'common_findings': [],
            'high_risk_files': []
        }
        
        # Aggregate results
        for file_path, file_result in files.items():
            if 'error' in file_result:
                continue
            
            # Count file types
            if 'file_type' in file_result:
                file_type = file_result['file_type'].get('detected_type', 'unknown')
                summary['file_types'][file_type] = summary['file_types'].get(file_type, 0) + 1
            
            # Count risk levels
            if 'security_scan' in file_result and 'risk_assessment' in file_result['security_scan']:
                risk_level = file_result['security_scan']['risk_assessment']['risk_level']
                summary['risk_levels'][risk_level] = summary['risk_levels'].get(risk_level, 0) + 1
                
                # Track high-risk files
                if risk_level in ['HIGH', 'CRITICAL']:
                    summary['high_risk_files'].append(file_path)
        
        return summary
    
    def _format_summary(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Format result as summary."""
        summary = result.get('summary', {})
        
        formatted = {
            'file_path': result.get('file_path'),
            'file_type': summary.get('file_info', {}).get('detected_type', 'unknown'),
            'file_size': summary.get('file_info', {}).get('file_size', 0),
            'risk_level': summary.get('risk_assessment', 'unknown'),
            'key_findings': summary.get('key_findings', []),
            'recommendations': summary.get('recommendations', [])
        }
        
        return formatted
    
    def _format_detailed(self, result: Dict[str, Any]) -> str:
        """Format result as detailed text report."""
        lines = []
        
        lines.append("=" * 60)
        lines.append("FILE METADATA ANALYSIS REPORT")
        lines.append("=" * 60)
        lines.append(f"File: {result.get('file_path', 'Unknown')}")
        lines.append("")
        
        # File type section
        if 'file_type' in result:
            lines.append("FILE TYPE DETECTION")
            lines.append("-" * 20)
            file_type = result['file_type']
            lines.append(f"Detected Type: {file_type.get('detected_type', 'Unknown')}")
            lines.append(f"Confidence: {file_type.get('confidence', 0):.1f}%")
            lines.append(f"MIME Type: {file_type.get('mime_type', 'Unknown')}")
            lines.append(f"File Size: {file_type.get('file_size', 0):,} bytes")
            lines.append("")
        
        # Content analysis section
        if 'content_analysis' in result:
            lines.append("CONTENT ANALYSIS")
            lines.append("-" * 15)
            content = result['content_analysis']
            
            if 'entropy_analysis' in content:
                entropy = content['entropy_analysis']['overall_entropy']
                lines.append(f"Overall Entropy: {entropy:.2f}")
            
            if 'strings_analysis' in content:
                strings = content['strings_analysis']
                lines.append(f"Total Strings: {strings.get('total_strings', 0)}")
                lines.append(f"Unique Strings: {strings.get('unique_strings', 0)}")
            
            if 'embedded_files' in content:
                embedded = content['embedded_files']
                lines.append(f"Embedded Files: {embedded.get('files_found', 0)}")
            
            lines.append("")
        
        # Security scan section
        if 'security_scan' in result:
            lines.append("SECURITY ANALYSIS")
            lines.append("-" * 17)
            security = result['security_scan']
            
            if 'risk_assessment' in security:
                risk = security['risk_assessment']
                lines.append(f"Risk Level: {risk['risk_level']}")
                lines.append(f"Risk Score: {risk['risk_score']}/100")
                
                if risk['risk_factors']:
                    lines.append("Risk Factors:")
                    for factor in risk['risk_factors']:
                        lines.append(f"  • {factor}")
                
                lines.append(f"Recommendation: {risk['recommendation']}")
            
            lines.append("")
        
        # Summary section
        if 'summary' in result:
            lines.append("SUMMARY")
            lines.append("-" * 7)
            summary = result['summary']
            
            if summary.get('key_findings'):
                lines.append("Key Findings:")
                for finding in summary['key_findings']:
                    lines.append(f"  • {finding}")
            
            lines.append("")
        
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def export_results(self, results: Dict[str, Any], output_path: str, format_type: str = 'json') -> None:
        """
        Export analysis results to file.
        
        Args:
            results: Analysis results to export
            output_path: Path to output file
            format_type: Export format ('json', 'txt', 'csv')
        """
        output_path_obj = Path(output_path)
        
        if format_type == 'json':
            with open(output_path_obj, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        
        elif format_type == 'txt':
            report = self._format_detailed(results)
            with open(output_path_obj, 'w') as f:
                f.write(report)
        
        elif format_type == 'csv':
            # Simple CSV format for multiple files
            import csv
            
            with open(output_path_obj, 'w', newline='') as f:
                writer = csv.writer(f)
                
                if 'files' in results:  # Directory analysis
                    writer.writerow(['File', 'Type', 'Size', 'Risk Level', 'Key Findings'])
                    
                    for file_path, file_result in results['files'].items():
                        if 'error' in file_result:
                            writer.writerow([file_path, 'ERROR', '', '', file_result['error']])
                            continue
                        
                        file_type = file_result.get('file_type', {}).get('detected_type', 'Unknown')
                        file_size = file_result.get('file_type', {}).get('file_size', 0)
                        risk_level = 'Unknown'
                        key_findings = []
                        
                        if 'security_scan' in file_result:
                            risk_level = file_result['security_scan'].get('risk_assessment', {}).get('risk_level', 'Unknown')
                        
                        if 'summary' in file_result:
                            key_findings = file_result['summary'].get('key_findings', [])
                        
                        writer.writerow([file_path, file_type, file_size, risk_level, '; '.join(key_findings)])
                
                else:  # Single file analysis
                    writer.writerow(['Property', 'Value'])
                    writer.writerow(['File Path', results.get('file_path', '')])
                    
                    if 'file_type' in results:
                        writer.writerow(['File Type', results['file_type'].get('detected_type', '')])
                        writer.writerow(['File Size', results['file_type'].get('file_size', '')])
                    
                    if 'security_scan' in results and 'risk_assessment' in results['security_scan']:
                        risk = results['security_scan']['risk_assessment']
                        writer.writerow(['Risk Level', risk.get('risk_level', '')])
                        writer.writerow(['Risk Score', risk.get('risk_score', '')])
        
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        self.logger.info(f"Results exported to {output_path}")
