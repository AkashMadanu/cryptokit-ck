"""
Metadata command implementation for CryptoKit (CK)

Command for file metadata analysis including type detection,
content analysis, and security scanning.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional

from ck.algorithms.metadata import MetadataService


class MetadataCommand:
    """Command for file metadata analysis."""
    
    def __init__(self):
        """Initialize the metadata command."""
        self.logger = None  # Will be set during execution
    
    def get_name(self) -> str:
        """Return command name."""
        return "metadata"
    
    def get_description(self) -> str:
        """Return command description."""
        return "Analyze file metadata, content, and security indicators"
    
    def get_usage(self) -> str:
        """Return command usage."""
        return """
Usage: ck metadata <file_or_directory> [options]

Analyze file metadata including type detection, content analysis, and security scanning.

Arguments:
  file_or_directory     Path to file or directory to analyze

Options:
  --recursive, -r       Analyze directory recursively
  --no-content         Skip content analysis  
  --no-security        Skip security scanning
  --format FORMAT      Output format: json, summary, detailed, csv (default: summary)
  --output FILE        Save results to file
  --max-size SIZE      Maximum file size to analyze in MB (default: 100)
  --max-files N        Maximum files to analyze in directory (default: 100)
  --pattern PATTERN    File pattern for directory analysis (default: *)
  --show-strings       Include string analysis in detailed output
  --risk-only          Show only files with security risks

Examples:
  ck metadata document.pdf
  ck metadata /path/to/files --recursive --format detailed
  ck metadata suspicious.exe --format json --output report.json
  ck metadata /downloads --risk-only --output security_report.csv
        """
    
    def add_arguments(self, parser):
        """Add command-specific arguments."""
        parser.add_argument(
            'path',
            help='Path to file or directory to analyze'
        )
        
        parser.add_argument(
            '--recursive', '-r',
            action='store_true',
            help='Analyze directory recursively'
        )
        
        parser.add_argument(
            '--no-content',
            action='store_true', 
            help='Skip content analysis'
        )
        
        parser.add_argument(
            '--no-security',
            action='store_true',
            help='Skip security scanning'
        )
        
        parser.add_argument(
            '--format',
            choices=['json', 'summary', 'detailed', 'csv'],
            default='summary',
            help='Output format (default: summary)'
        )
        
        parser.add_argument(
            '--output', '-o',
            help='Save results to file'
        )
        
        parser.add_argument(
            '--max-size',
            type=int,
            default=100,
            help='Maximum file size to analyze in MB (default: 100)'
        )
        
        parser.add_argument(
            '--max-files',
            type=int,
            default=100,
            help='Maximum files to analyze in directory (default: 100)'
        )
        
        parser.add_argument(
            '--pattern',
            default='*',
            help='File pattern for directory analysis (default: *)'
        )
        
        parser.add_argument(
            '--show-strings',
            action='store_true',
            help='Include string analysis in detailed output'
        )
        
        parser.add_argument(
            '--risk-only',
            action='store_true',
            help='Show only files with security risks'
        )
    
    def execute(self, args) -> int:
        """Execute the metadata command."""
        try:
            # Initialize service
            metadata_service = MetadataService()
            
            # Prepare options
            options = {
                'include_content': not args.no_content,
                'include_security': not args.no_security,
                'max_file_size': args.max_size * 1024 * 1024,  # Convert MB to bytes
                'output_format': args.format
            }
            
            path = Path(args.path)
            
            if not path.exists():
                self.logger.error(f"Path does not exist: {args.path}")
                return 1
            
            # Analyze file or directory
            if path.is_file():
                result = self._analyze_single_file(metadata_service, path, options, args)
            elif path.is_dir():
                # Add directory-specific options
                options.update({
                    'recursive': args.recursive,
                    'file_pattern': args.pattern,
                    'max_files': args.max_files
                })
                result = self._analyze_directory(metadata_service, path, options, args)
            else:
                self.logger.error(f"Path is neither file nor directory: {args.path}")
                return 1
            
            # Filter results if risk-only
            if args.risk_only:
                result = self._filter_risk_only(result)
            
            # Output results
            self._output_results(result, args)
            
            return 0
            
        except Exception as e:
            self.logger.error(f"Metadata analysis failed: {e}")
            return 1
    
    def _analyze_single_file(self, service: MetadataService, file_path: Path, options: Dict[str, Any], args) -> Dict[str, Any]:
        """Analyze a single file."""
        self.logger.info(f"Analyzing file: {file_path}")
        
        result = service.analyze_file(str(file_path), options)
        
        if 'error' in result:
            self.logger.error(f"Analysis failed: {result['error']}")
        
        return result
    
    def _analyze_directory(self, service: MetadataService, directory_path: Path, options: Dict[str, Any], args) -> Dict[str, Any]:
        """Analyze a directory."""
        self.logger.info(f"Analyzing directory: {directory_path}")
        
        if options['recursive']:
            self.logger.info("Recursive analysis enabled")
        
        result = service.analyze_directory(str(directory_path), options)
        
        # Log summary
        summary = result.get('summary', {})
        self.logger.info(f"Analyzed {result.get('files_analyzed', 0)} files")
        
        if summary.get('high_risk_files'):
            self.logger.warning(f"Found {len(summary['high_risk_files'])} high-risk files")
        
        return result
    
    def _filter_risk_only(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Filter results to show only files with security risks."""
        if 'files' in result:  # Directory analysis
            filtered_files = {}
            
            for file_path, file_result in result['files'].items():
                if 'error' in file_result:
                    continue
                
                # Check if file has security risks
                if 'security_scan' in file_result:
                    risk_level = file_result['security_scan'].get('risk_assessment', {}).get('risk_level')
                    if risk_level in ['MEDIUM', 'HIGH', 'CRITICAL']:
                        filtered_files[file_path] = file_result
            
            # Update result
            result['files'] = filtered_files
            result['files_analyzed'] = len(filtered_files)
            result['filtered'] = 'risk_only'
        
        else:  # Single file analysis
            # Check if single file has risks
            if 'security_scan' in result:
                risk_level = result['security_scan'].get('risk_assessment', {}).get('risk_level')
                if risk_level not in ['MEDIUM', 'HIGH', 'CRITICAL']:
                    result = {'message': 'No security risks detected', 'original_result': result}
        
        return result
    
    def _output_results(self, result: Dict[str, Any], args) -> None:
        """Output analysis results."""
        # Determine output format
        output_format = args.format
        
        if args.output:
            # Save to file
            output_path = Path(args.output)
            
            # Determine format from file extension if not specified
            if output_format == 'summary' and output_path.suffix:
                if output_path.suffix.lower() == '.json':
                    output_format = 'json'
                elif output_path.suffix.lower() == '.csv':
                    output_format = 'csv'
                elif output_path.suffix.lower() == '.txt':
                    output_format = 'detailed'
            
            self._save_to_file(result, output_path, output_format)
            self.logger.info(f"Results saved to: {args.output}")
        
        else:
            # Output to console
            self._print_results(result, output_format, args)
    
    def _save_to_file(self, result: Dict[str, Any], output_path: Path, format_type: str) -> None:
        """Save results to file."""
        if format_type == 'json':
            with open(output_path, 'w') as f:
                json.dump(result, f, indent=2, default=str)
        
        elif format_type == 'csv':
            self._save_csv(result, output_path)
        
        elif format_type == 'detailed':
            content = self._format_detailed_text(result)
            with open(output_path, 'w') as f:
                f.write(content)
        
        else:  # summary format
            content = self._format_summary_text(result)
            with open(output_path, 'w') as f:
                f.write(content)
    
    def _save_csv(self, result: Dict[str, Any], output_path: Path) -> None:
        """Save results as CSV."""
        import csv
        
        with open(output_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            
            if 'files' in result:  # Directory analysis
                writer.writerow(['File', 'Type', 'Size (bytes)', 'Risk Level', 'Risk Score', 'Key Findings'])
                
                for file_path, file_result in result['files'].items():
                    if 'error' in file_result:
                        writer.writerow([file_path, 'ERROR', '', '', '', file_result['error']])
                        continue
                    
                    file_type = file_result.get('file_type', {}).get('detected_type', 'Unknown')
                    file_size = file_result.get('file_type', {}).get('file_size', 0)
                    
                    risk_level = 'Unknown'
                    risk_score = 0
                    if 'security_scan' in file_result and 'risk_assessment' in file_result['security_scan']:
                        risk_assessment = file_result['security_scan']['risk_assessment']
                        risk_level = risk_assessment.get('risk_level', 'Unknown')
                        risk_score = risk_assessment.get('risk_score', 0)
                    
                    key_findings = []
                    if 'summary' in file_result:
                        key_findings = file_result['summary'].get('key_findings', [])
                    
                    writer.writerow([
                        file_path, file_type, file_size, risk_level, risk_score,
                        '; '.join(key_findings[:3])  # Limit findings
                    ])
            
            else:  # Single file analysis
                writer.writerow(['Property', 'Value'])
                writer.writerow(['File Path', result.get('file_path', '')])
                
                if 'file_type' in result:
                    writer.writerow(['File Type', result['file_type'].get('detected_type', '')])
                    writer.writerow(['File Size', result['file_type'].get('file_size', '')])
                    writer.writerow(['MIME Type', result['file_type'].get('mime_type', '')])
                
                if 'security_scan' in result and 'risk_assessment' in result['security_scan']:
                    risk = result['security_scan']['risk_assessment']
                    writer.writerow(['Risk Level', risk.get('risk_level', '')])
                    writer.writerow(['Risk Score', risk.get('risk_score', '')])
                    
                    if risk.get('risk_factors'):
                        writer.writerow(['Risk Factors', '; '.join(risk['risk_factors'])])
    
    def _print_results(self, result: Dict[str, Any], format_type: str, args) -> None:
        """Print results to console."""
        if format_type == 'json':
            print(json.dumps(result, indent=2, default=str))
        
        elif format_type == 'detailed':
            print(self._format_detailed_text(result))
        
        elif format_type == 'csv':
            # For console CSV, just show headers and first few rows
            self._print_csv_preview(result)
        
        else:  # summary format (default)
            print(self._format_summary_text(result))
    
    def _format_summary_text(self, result: Dict[str, Any]) -> str:
        """Format results as summary text."""
        lines = []
        
        if 'files' in result:  # Directory analysis
            lines.append(f"📁 Directory Analysis: {result.get('directory_path', 'Unknown')}")
            lines.append(f"Files analyzed: {result.get('files_analyzed', 0)}")
            lines.append("")
            
            # Summary statistics
            summary = result.get('summary', {})
            
            if summary.get('file_types'):
                lines.append("📄 File Types:")
                for file_type, count in sorted(summary['file_types'].items()):
                    lines.append(f"  {file_type}: {count}")
                lines.append("")
            
            if summary.get('risk_levels'):
                lines.append("🛡️ Risk Assessment:")
                risk_order = ['MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
                for risk_level in risk_order:
                    if risk_level in summary['risk_levels']:
                        count = summary['risk_levels'][risk_level]
                        emoji = self._get_risk_emoji(risk_level)
                        lines.append(f"  {emoji} {risk_level}: {count}")
                lines.append("")
            
            if summary.get('high_risk_files'):
                lines.append("⚠️ High-Risk Files:")
                for file_path in summary['high_risk_files'][:10]:  # Show first 10
                    lines.append(f"  {file_path}")
                if len(summary['high_risk_files']) > 10:
                    lines.append(f"  ... and {len(summary['high_risk_files']) - 10} more")
        
        else:  # Single file analysis
            lines.append(f"📄 File Analysis: {result.get('file_path', 'Unknown')}")
            lines.append("")
            
            # File type info
            if 'file_type' in result:
                file_type = result['file_type']
                lines.append(f"Type: {file_type.get('detected_type', 'Unknown')}")
                lines.append(f"Size: {file_type.get('file_size', 0):,} bytes")
                lines.append(f"MIME: {file_type.get('mime_type', 'Unknown')}")
                lines.append(f"Confidence: {file_type.get('confidence', 0):.1f}%")
                lines.append("")
            
            # Security assessment
            if 'security_scan' in result and 'risk_assessment' in result['security_scan']:
                risk = result['security_scan']['risk_assessment']
                risk_level = risk.get('risk_level', 'UNKNOWN')
                emoji = self._get_risk_emoji(risk_level)
                
                lines.append(f"🛡️ Security Assessment:")
                lines.append(f"  Risk Level: {emoji} {risk_level}")
                lines.append(f"  Risk Score: {risk.get('risk_score', 0)}/100")
                
                if risk.get('risk_factors'):
                    lines.append(f"  Risk Factors:")
                    for factor in risk['risk_factors'][:5]:  # Show first 5
                        lines.append(f"    • {factor}")
                lines.append("")
            
            # Key findings
            if 'summary' in result and result['summary'].get('key_findings'):
                lines.append("🔍 Key Findings:")
                for finding in result['summary']['key_findings'][:5]:
                    lines.append(f"  • {finding}")
                lines.append("")
        
        return "\n".join(lines)
    
    def _format_detailed_text(self, result: Dict[str, Any]) -> str:
        """Format results as detailed text."""
        if 'files' in result:
            # For directory analysis, show summary + details for high-risk files
            lines = [self._format_summary_text(result)]
            
            lines.append("=" * 60)
            lines.append("DETAILED ANALYSIS - HIGH RISK FILES")
            lines.append("=" * 60)
            
            high_risk_count = 0
            for file_path, file_result in result['files'].items():
                if 'error' in file_result:
                    continue
                
                # Only show detailed info for high-risk files
                if 'security_scan' in file_result:
                    risk_level = file_result['security_scan'].get('risk_assessment', {}).get('risk_level')
                    if risk_level in ['HIGH', 'CRITICAL']:
                        lines.append(f"\n📄 {file_path}")
                        lines.append("-" * 40)
                        lines.append(self._format_single_file_details(file_result))
                        high_risk_count += 1
                        
                        if high_risk_count >= 10:  # Limit detailed output
                            lines.append("\n... (showing first 10 high-risk files)")
                            break
            
            if high_risk_count == 0:
                lines.append("No high-risk files found.")
            
            return "\n".join(lines)
        
        else:
            # Single file - show full details
            return self._format_single_file_details(result)
    
    def _format_single_file_details(self, file_result: Dict[str, Any]) -> str:
        """Format detailed information for a single file."""
        lines = []
        
        # File type details
        if 'file_type' in file_result:
            file_type = file_result['file_type']
            lines.append("📁 File Type Information:")
            lines.append(f"  Detected Type: {file_type.get('detected_type', 'Unknown')}")
            lines.append(f"  MIME Type: {file_type.get('mime_type', 'Unknown')}")
            lines.append(f"  File Size: {file_type.get('file_size', 0):,} bytes")
            lines.append(f"  Confidence: {file_type.get('confidence', 0):.1f}%")
            
            if file_type.get('magic_number'):
                lines.append(f"  Magic Number: {file_type['magic_number']}")
            
            lines.append("")
        
        # Content analysis details
        if 'content_analysis' in file_result:
            content = file_result['content_analysis']
            lines.append("📊 Content Analysis:")
            
            if 'entropy_analysis' in content:
                entropy = content['entropy_analysis']
                lines.append(f"  Overall Entropy: {entropy.get('overall_entropy', 0):.2f}")
                lines.append(f"  Classification: {entropy.get('classification', 'Unknown')}")
            
            if 'strings_analysis' in content:
                strings = content['strings_analysis']
                lines.append(f"  Total Strings: {strings.get('total_strings', 0)}")
                lines.append(f"  Unique Strings: {strings.get('unique_strings', 0)}")
                lines.append(f"  Average Length: {strings.get('average_length', 0):.1f}")
            
            if 'embedded_files' in content:
                embedded = content['embedded_files']
                lines.append(f"  Embedded Files: {embedded.get('files_found', 0)}")
                if embedded.get('file_types'):
                    lines.append(f"  Embedded Types: {', '.join(embedded['file_types'])}")
            
            lines.append("")
        
        # Security scan details
        if 'security_scan' in file_result:
            security = file_result['security_scan']
            lines.append("🛡️ Security Analysis:")
            
            if 'risk_assessment' in security:
                risk = security['risk_assessment']
                risk_level = risk.get('risk_level', 'UNKNOWN')
                emoji = self._get_risk_emoji(risk_level)
                
                lines.append(f"  Risk Level: {emoji} {risk_level}")
                lines.append(f"  Risk Score: {risk.get('risk_score', 0)}/100")
                
                if risk.get('risk_factors'):
                    lines.append("  Risk Factors:")
                    for factor in risk['risk_factors']:
                        lines.append(f"    • {factor}")
                
                lines.append(f"  Recommendation: {risk.get('recommendation', 'None')}")
            
            # Pattern analysis
            if 'pattern_analysis' in security:
                patterns = security['pattern_analysis']
                if patterns.get('pattern_details'):
                    lines.append("  Suspicious Patterns:")
                    for category, details in patterns['pattern_details'].items():
                        lines.append(f"    {category}: {details['count']} matches")
            
            lines.append("")
        
        return "\n".join(lines)
    
    def _print_csv_preview(self, result: Dict[str, Any]) -> None:
        """Print CSV preview to console."""
        print("CSV Format Preview (use --output to save full CSV):")
        print("-" * 50)
        
        if 'files' in result:
            print("File,Type,Size,Risk Level,Risk Score,Key Findings")
            
            count = 0
            for file_path, file_result in result['files'].items():
                if count >= 5:  # Show only first 5 rows
                    print("... (use --output to save complete results)")
                    break
                
                if 'error' in file_result:
                    print(f'"{file_path}",ERROR,,,,"Error: {file_result["error"]}"')
                    continue
                
                file_type = file_result.get('file_type', {}).get('detected_type', 'Unknown')
                file_size = file_result.get('file_type', {}).get('file_size', 0)
                
                risk_level = 'Unknown'
                risk_score = 0
                if 'security_scan' in file_result and 'risk_assessment' in file_result['security_scan']:
                    risk_assessment = file_result['security_scan']['risk_assessment']
                    risk_level = risk_assessment.get('risk_level', 'Unknown')
                    risk_score = risk_assessment.get('risk_score', 0)
                
                key_findings = []
                if 'summary' in file_result:
                    key_findings = file_result['summary'].get('key_findings', [])
                
                findings_str = '; '.join(key_findings[:2])  # Show first 2
                print(f'"{file_path}",{file_type},{file_size},{risk_level},{risk_score},"{findings_str}"')
                count += 1
        
        else:
            print("Property,Value")
            print(f'"File Path","{result.get("file_path", "")}"')
            
            if 'file_type' in result:
                print(f'"File Type","{result["file_type"].get("detected_type", "")}"')
                print(f'"File Size","{result["file_type"].get("file_size", "")}"')
            
            if 'security_scan' in result and 'risk_assessment' in result['security_scan']:
                risk = result['security_scan']['risk_assessment']
                print(f'"Risk Level","{risk.get("risk_level", "")}"')
                print(f'"Risk Score","{risk.get("risk_score", "")}"')
    
    def _get_risk_emoji(self, risk_level: str) -> str:
        """Get emoji for risk level."""
        emoji_map = {
            'MINIMAL': '✅',
            'LOW': '🟢', 
            'MEDIUM': '🟡',
            'HIGH': '🟠',
            'CRITICAL': '🔴'
        }
        return emoji_map.get(risk_level.upper(), '❓')


def create_command():
    """Factory function to create the command."""
    return MetadataCommand()
