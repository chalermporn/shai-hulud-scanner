# Shai-Hulud 2.0 Scanner

A security scanner for detecting indicators of the Shai-Hulud 2.0 supply chain attack in npm projects.

Based on research from [Socket.dev](https://socket.dev/blog/shai-hulud-strikes-again-v2), Datadog, and Wiz Security.

## About

Shai-Hulud 2.0 is a sophisticated supply chain attack targeting npm packages. This scanner helps detect:

- Compromised npm packages from the IOC (Indicators of Compromise) list
- Malicious files (`setup_bun.js`, `bun_environment.js`)
- Suspicious preinstall/postinstall scripts
- GitHub infection markers (malicious workflows, branches)
- Malicious self-hosted GitHub Actions runners

## Installation

```bash
bun install
```

## Usage

### Scan current directory

```bash
bun start
```

### Scan specific directory

```bash
bun start /path/to/project
```

### Convert IOC list

```bash
bun run convert
```

This parses `shai.txt` and generates `ioc-packages.ts` with the latest IOC data.

## Features

### Package Scanning
- Scans `node_modules` for compromised packages
- Checks lock files (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`)
- Downloads latest IOC list from Datadog's GitHub repository

### Malicious File Detection
- Detects known malicious files by name and SHA-1 hash
- Identifies large obfuscated JavaScript files (potential payloads)
- Scans for suspicious patterns in code

### Script Analysis
- Checks `package.json` for suspicious preinstall/postinstall scripts
- Detects commands that execute malicious files

### GitHub Markers
- Scans for suspicious branches containing "shai-hulud"
- Checks GitHub Actions workflows for malicious content
- Detects backdoor workflows (e.g., `discussion.yaml`)
- Identifies malicious self-hosted runners
- Checks for running malicious processes

### Reporting
- Generates detailed JSON reports in `export-report/`
- Color-coded terminal output
- Severity classification (CRITICAL, HIGH)
- Actionable remediation steps

## Output

The scanner generates:
- Real-time terminal output with color-coded findings
- JSON report in `export-report/shai-hulud-report-{timestamp}.json`

### Exit Codes
- `0` - No issues found or warnings only
- `1` - Critical issues detected

## Example Output

```
═════════════════════════════════════════════════════════════════
  Shai-Hulud 2.0 Supply Chain Attack Scanner v1.0
═════════════════════════════════════════════════════════════════

[INFO] Scanning directory: /path/to/project
[INFO] Scan started at: 2025-12-01T12:00:00.000Z

═════════════════════════════════════════════════════════════════
  Downloading Latest IOC List
═════════════════════════════════════════════════════════════════
[✓] Downloaded IOC list: 245 packages

...

[✓] No Shai-Hulud 2.0 indicators detected
```

## Remediation

If compromised packages are detected:

1. **Immediately delete node_modules**
   ```bash
   rm -rf node_modules
   ```

2. **Clear package manager caches**
   ```bash
   npm cache clean --force
   # or
   yarn cache clean
   # or
   pnpm store prune
   ```

3. **Rotate all credentials**
   - npm tokens
   - GitHub Personal Access Tokens
   - SSH keys
   - Cloud provider credentials (AWS, GCP, Azure)

4. **Check GitHub for unauthorized repositories**
   - Look for repos with "Sha1-Hulud" in the description

5. **Review CI/CD pipelines**
   - Check GitHub Actions workflows for unauthorized changes
   - Remove malicious self-hosted runners

6. **Pin dependencies to safe versions**
   - Use versions before November 21, 2025

## Prevention

- Enable phishing-resistant MFA for all developer accounts
- Use npm's trusted publishing feature
- Disable lifecycle scripts in CI: `--ignore-scripts`
- Pin dependencies to known safe versions
- Regularly scan projects with this tool

## How It Works

1. Downloads the latest IOC list from Datadog's GitHub
2. Scans `node_modules` directories for compromised package versions
3. Analyzes lock files for references to compromised packages
4. Searches for known malicious files and calculates their SHA-1 hashes
5. Examines `package.json` scripts for suspicious commands
6. Checks Git repository for infection markers
7. Scans for malicious GitHub Actions workflows
8. Detects malicious self-hosted runners
9. Generates comprehensive report with remediation steps

## Technical Details

- **Runtime**: Bun
- **Language**: TypeScript
- **IOC Source**: https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv
- **Attack Timeline**: Started November 21, 2025

## Project Structure

```
shai-hulud-scanner/
├── src/
│   ├── index.ts          # Main scanner
│   ├── parse.ts          # IOC parser
│   ├── ioc-packages.ts   # Generated IOC list
│   └── shai.txt          # Raw IOC data
├── export-report/        # Scan reports
├── package.json
├── tsconfig.json
└── README.md
```

## License

This project was created using [Bun](https://bun.sh).

## References

- [Socket.dev: Shai-Hulud 2.0 Analysis](https://socket.dev/blog/shai-hulud-strikes-again-v2)
- [Datadog IOC Repository](https://github.com/DataDog/indicators-of-compromise/tree/main/shai-hulud-2.0)
- [Wiz Security Research](https://www.wiz.io/blog/shai-hulud-2-supply-chain-attack)
