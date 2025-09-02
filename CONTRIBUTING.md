# Contributing to CryptoKit (CK)

Thank you for your interest in contributing to CryptoKit! This document provides guidelines for contributing to the project.

## Project Overview

CryptoKit is a comprehensive cryptography toolkit designed for educational and practical use. The project follows a phase-based development approach:

- **Phase 1**: Symmetric Encryption *(Current)*
- **Phase 2**: Hashing & Verification  
- **Phase 3**: Hash Analysis & Cracking
- **Phase 4**: Steganography
- **Phase 5**: File Metadata Analysis

## Getting Started

### Prerequisites
- Python 3.9 or higher
- Git
- Linux environment (primary target)

### Development Setup
```bash
# Clone the repository
git clone https://github.com/AkashMadanu/cryptokit-ck.git
cd cryptokit-ck

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Run tests
python -m pytest tests/
```

## How to Contribute

### 1. Issues
- **Bug Reports**: Use the bug report template
- **Feature Requests**: Use the feature request template
- **Questions**: Use GitHub Discussions

### 2. Pull Requests

#### Process
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Commit your changes (`git commit -m 'Add amazing feature'`)
7. Push to the branch (`git push origin feature/amazing-feature`)
8. Open a Pull Request

#### Pull Request Requirements
- [ ] Code follows PEP 8 style guidelines
- [ ] All tests pass
- [ ] New features include tests
- [ ] Documentation is updated
- [ ] Commit messages are descriptive

## Development Guidelines

### Code Style
- Follow PEP 8 style guide
- Use type hints for all functions
- Write comprehensive docstrings
- Maximum line length: 88 characters (Black formatter)

### Testing
- Write unit tests for all new functionality
- Maintain test coverage above 80%
- Use pytest for testing framework
- Include integration tests where appropriate

### Documentation
- Update README.md for user-facing changes
- Update PROJECT_PLAN.md for architectural changes
- Include docstrings for all public functions
- Add examples for new features

### Commit Messages
Use conventional commit format:
```
<type>: <description>

[optional body]

Examples:
feat: add ChaCha20 encryption algorithm
fix: resolve configuration file loading issue
docs: update installation instructions
test: add unit tests for hash detection
refactor: reorganize encryption module structure
```

## Architecture Guidelines

### Module Structure
Each phase has its own module with standardized structure:
```
ck/<module>/
├── __init__.py          # Public API exports
├── algorithms/          # Algorithm implementations
├── managers.py         # High-level management classes
└── utils.py            # Module-specific utilities
```

### Interface Implementation
- Implement abstract base classes from `ck.core.interfaces`
- Follow established patterns from existing modules
- Ensure consistent error handling

### Configuration
- Add new settings to `config/default.yaml`
- Use the ConfigManager for all configuration access
- Validate configuration values

## Code Review Process

### Review Criteria
- Functionality works as intended
- Code follows project conventions
- Tests are comprehensive
- Documentation is clear and complete
- Security considerations are addressed

### Review Timeline
- Maintainers will review PRs within 48-72 hours
- Address feedback promptly
- Be responsive to questions and suggestions

## Bug Reports

### Information to Include
- Operating system and version
- Python version
- CryptoKit version
- Steps to reproduce
- Expected vs actual behavior
- Error messages and logs

### Priority Labels
- **Critical**: Security vulnerabilities, data corruption
- **High**: Breaks existing functionality
- **Medium**: New feature bugs, performance issues
- **Low**: Documentation, minor UI issues

## Feature Requests

### Guidelines
- Check existing issues first
- Provide clear use case
- Consider which phase it belongs to
- Include implementation ideas if possible

### Acceptance Criteria
- Aligns with project goals
- Doesn't break existing functionality
- Has clear scope and requirements
- Community interest/support

## Development Phases

### Current Phase: Symmetric Encryption
**Focus Areas:**
- AES (CBC, GCM modes)
- ChaCha20-Poly1305
- Key derivation (PBKDF2, Argon2)
- File operations

**How to Contribute:**
- Implement new algorithms
- Improve key management
- Add benchmarking
- Enhance security features

### Future Phases
See [PROJECT_PLAN.md](PROJECT_PLAN.md) for detailed roadmaps of upcoming phases.

## Security

### Reporting Security Issues
- **DO NOT** create public issues for security vulnerabilities
- Email maintainers directly
- Provide detailed reproduction steps
- Allow time for fix before public disclosure

### Security Considerations
- Follow secure coding practices
- Validate all inputs
- Handle sensitive data properly
- Use cryptographically secure random numbers

## Getting Help

### Channels
- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and general discussion
- **Pull Request Comments**: Code-specific questions

### Response Times
- Issues: 24-48 hours
- Pull Requests: 48-72 hours
- Discussions: Best effort

## Recognition

Contributors will be recognized in:
- README.md contributors section
- Release notes
- GitHub contributors page

## License

By contributing to CryptoKit, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to CryptoKit! Together we can build an excellent cryptography toolkit for education and practical use.
