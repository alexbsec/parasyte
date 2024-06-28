# Contributing

We warmly welcome contributions to the Parasyte project. Your support helps us to improve the simulation and deepen our collective understanding of cybersecurity. This document outlines our contribution guidelines to ensure a productive and collaborative environment.

## Code Contribution

Before you begin writing code, please consider the following guidelines to ensure consistency and quality in our project's codebase.

### Coding Standards

- Google C++ Style Guide: All code must adhere to the [Google C++ Style Guide](https://google.github.io/styleguide/cppguide.html). This includes conventions on formatting, naming, usage, and more. 
- The filenames must capitalize every new word, different from Google: NetScanner (Net and Scanner are capitalized).
- Exception handling: Avoid using throw statements for exception handling in nested functions. Instead, prefer return codes or error objects for error handling in lower-level functions, and reserve exceptions for unexpected errors that the immediate function cannot handle.

### Pull Requests

1. Fork and Clone: Fork the project repository and clone it locally to work on your contribution.
    
2. Branch Naming: Create a new branch for your contribution. Name it meaningfully, preferably starting with the type of contribution (e.g., feature-add-network-scanning, bugfix-memory-leak).

3. Commit Messages: Write clear, concise commit messages that describe the changes made. Begin with a short summary (50 characters or less), followed by a detailed description if necessary.

4. Testing: Add tests for new features or bug fixes whenever possible. Ensure existing tests pass with your changes.

5. Documentation: Update the README.md, architecture.md, or any other documentation as necessary to reflect your changes or additions.

6. Review: Submit a pull request to the main branch. Ensure your PR description clearly describes the problem and solution, including any relevant issue numbers.

### Review Process

The project maintainers will review your pull request. They may request changes or provide feedback. Engage in this process constructively to ensure your contribution meets the project's standards and objectives. Once approved, a maintainer will merge your pull request.

## Legal Notice

By contributing to the Parasyte project, you agree that your contributions will be licensed under the same license that covers the project (typically MIT License). See the LICENSE.md file in the repository for details.

## Acknowledgments

Your contributions are greatly appreciated. Together, we can advance the field of cybersecurity research and education.