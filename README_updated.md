
# Repository Audit Scripts 🚀

Welcome to the **Repository Audit Scripts** suite! This collection of tools helps automate evaluation and auditing of various components in software development, including GitHub repositories, Docker images, and NPM packages.

## Why These Scripts? 🤔

Let’s face it: manual auditing is tedious and error-prone. These scripts help automate checks for best practices, license presence, last activity, security policies, and more. Whether you're doing compliance, security, or general code hygiene checks, these tools make it easier and faster.

## Features ✨

### `githubaudit.py`
- **Repository Info:** Get detailed information about the repository, including its license and primary language.
- **Security Policy Check:** Verifies the existence of a security policy.
- **Activity Audit:** Checks the latest commit date to assess project activity.
- **License Audit:** Verifies whether a license file is present.

### `dockeraudit.py`
- **Dockerfile Linter:** Scans Dockerfiles for common security and style issues.
- **Best Practices Check:** Highlights risky instructions and deprecated syntax.
- **Output Summary:** Presents a summary of key issues to fix.

### `npmaudit.py`
- **Package Vulnerability Scan:** Checks `package.json` and `package-lock.json` for known vulnerabilities.
- **Dependency Health:** Reports outdated packages or packages with known issues.
- **Audit Score:** Provides a summary score based on issues found.

## Installation 🛠

Install the required Python packages using pip:

```bash
pip install -r requirements.txt
```

## Usage 🚦

Each script can be run independently depending on what you're auditing:

### GitHub Repository Audit
```bash
python githubaudit.py --repo <owner/repo>
```

### Dockerfile Audit
```bash
python dockeraudit.py --file path/to/Dockerfile
```

### NPM Package Audit
```bash
python npmaudit.py --path path/to/npm/project
```

## Requirements 📦

See `requirements.txt` for the full list of dependencies.

## License 📄

See the [LICENSE](LICENSE) file for details.

## Security Policy 🛡

See the [SECURITY.md](SECURITY.md) file for security reporting guidelines.

---

Make your audits easier, faster, and more consistent with this suite of tools. ✨
