# Contributing to mangosint

Thank you for your interest in contributing to mangosint! This document provides guidelines and information for contributors.

## Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/k6w/mangosint.git
   cd mangosint
   ```

2. **Install development dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```

3. **Set up pre-commit hooks** (optional but recommended):
   ```bash
   pre-commit install
   ```

## Development Workflow

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** and ensure:
   - Code follows the existing style (checked by ruff)
   - Tests pass
   - Documentation is updated if needed

3. **Run tests**:
   ```bash
   python -m pytest
   ```

4. **Run linting**:
   ```bash
   ruff check .
   ruff format .
   ```

5. **Commit your changes**:
   ```bash
   git commit -m "feat: add your feature description"
   ```

6. **Push and create a pull request**:
   ```bash
   git push origin feature/your-feature-name
   ```

## Code Style

- **Formatting**: Black with 88 character line length
- **Linting**: Ruff for fast Python linting
- **Type hints**: Use type hints where possible
- **Docstrings**: Use Google-style docstrings

## Adding New Modules

When adding new intelligence modules:

1. Create a new file in `src/mangosint/modules/`
2. Implement the `Module` base class
3. Add proper error handling and logging
4. Update the README with module information
5. Add tests for the new module

## Testing

- Write unit tests for new functionality
- Test with both mocked and real API calls (where safe)
- Ensure proxy functionality works correctly
- Test error conditions and edge cases

## Security Considerations

- Never commit API keys or sensitive credentials
- Ensure all network requests go through configured proxies
- Validate user input to prevent injection attacks
- Follow privacy-first principles

## Reporting Issues

- Use GitHub issues for bug reports and feature requests
- Include detailed reproduction steps
- Specify your environment (OS, Python version, etc.)

## License

By contributing to mangosint, you agree that your contributions will be licensed under the MIT License.