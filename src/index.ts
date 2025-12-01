/**
 * Shai-Hulud 2.0 Supply Chain Attack Scanner
 * ============================================
 * Based on: https://socket.dev/blog/shai-hulud-strikes-again-v2
 *
 * Scans npm projects for indicators of the Shai-Hulud 2.0 supply chain attack.
 *
 * Features:
 * - Downloads latest IOC list from Datadog
 * - Scans node_modules for compromised packages
 * - Checks lock files (package-lock.json, yarn.lock, pnpm-lock.yaml)
 * - Detects malicious files (setup_bun.js, bun_environment.js)
 * - Identifies suspicious preinstall scripts
 * - Checks for GitHub infection markers
 * - Validates file hashes against known malware
 *
 * Usage:
 *   node shai-hulud-scanner.js [directory]
 *   npx shai-hulud-scanner [directory]
 */

import { execSync } from 'child_process'
import crypto from 'crypto'
import fs from 'fs'
import https from 'https'
import path from 'path'

// ============================================================================
// Types and Interfaces
// ============================================================================

interface Config {
  iocUrl: string
  maliciousFileHashes: Record<string, string>
  maliciousFileNames: string[]
  suspiciousPatterns: RegExp[]
  criticalDate: Date
}

interface CompromisedPackage {
  package: string
  version: string
  location: string
  severity: string
  source?: string
}

interface MaliciousFile {
  file: string
  sha1: string
  matched: string
  severity: string
}

interface SuspiciousScript {
  file: string
  script: string
  command: string
  severity: string
}

interface GitHubMarker {
  type: string
  details?: string
  file?: string
  pattern?: string
  path?: string
  severity: string
}

interface Warning {
  type: string
  file: string
  size: number
  reason: string
}

interface ScanResults {
  scannedPackages: number
  compromisedPackages: CompromisedPackage[]
  maliciousFiles: MaliciousFile[]
  suspiciousScripts: SuspiciousScript[]
  githubMarkers: GitHubMarker[]
  warnings: Warning[]
  startTime: number
}

interface IOCPackages {
  [packageName: string]: string[]
}

interface FindFilesOptions {
  maxDepth?: number
  excludeNodeModules?: boolean
}

// ============================================================================
// Configuration
// ============================================================================

const CONFIG: Config = {
  iocUrl: 'https://raw.githubusercontent.com/DataDog/indicators-of-compromise/main/shai-hulud-2.0/consolidated_iocs.csv',
  maliciousFileHashes: {
    // SHA-1 hashes of known malicious files
    d60ec97eea19fffb4809bc35b91033b52490ca11: 'bun_environment.js (Shai-Hulud 2.0 payload)',
  },
  maliciousFileNames: [
    'setup_bun.js',
    'bun_environment.js',
  ],
  suspiciousPatterns: [
    /Sha1-Hulud/i,
    /SHA1HULUD/i,
    /webhook\.site\/bb8ca5f6/,
    /The Second Coming/i,
  ],
  criticalDate: new Date('2025-11-21'), // Attack started
}

// ============================================================================
// Colors for terminal output
// ============================================================================

const colors = {
  reset: '\x1B[0m',
  bold: '\x1B[1m',
  red: '\x1B[31m',
  green: '\x1B[32m',
  yellow: '\x1B[33m',
  blue: '\x1B[34m',
  cyan: '\x1B[36m',
  magenta: '\x1B[35m',
}

const log = {
  info: (msg: string) => console.log(`${colors.blue}[INFO]${colors.reset} ${msg}`),
  success: (msg: string) => console.log(`${colors.green}[✓]${colors.reset} ${msg}`),
  warning: (msg: string) => console.log(`${colors.yellow}[⚠]${colors.reset} ${msg}`),
  error: (msg: string) => console.log(`${colors.red}[✗]${colors.reset} ${msg}`),
  header: (msg: string) => {
    console.log('')
    console.log(`${colors.bold}${colors.cyan}${'═'.repeat(65)}${colors.reset}`)
    console.log(`${colors.bold}${colors.cyan}  ${msg}${colors.reset}`)
    console.log(`${colors.bold}${colors.cyan}${'═'.repeat(65)}${colors.reset}`)
  },
}

// ============================================================================
// Scanner Results
// ============================================================================

const results: ScanResults = {
  scannedPackages: 0,
  compromisedPackages: [],
  maliciousFiles: [],
  suspiciousScripts: [],
  githubMarkers: [],
  warnings: [],
  startTime: Date.now(),
}

// ============================================================================
// Banner
// ============================================================================

function printBanner() {
  console.log(`${colors.bold}${colors.red}`)
  console.log(`
   _____ _           _       _    _       _           _   ___    ___
  / ____| |         (_)     | |  | |     | |         | | |__ \\  / _ \\
 | (___ | |__   __ _ _      | |__| |_   _| |_   _  __| |    ) || | | |
  \\___ \\| '_ \\ / _\` | |_____|  __  | | | | | | | |/ _\` |   / / | | | |
  ____) | | | | (_| | |_____| |  | | |_| | | |_| | (_| |  / /_ | |_| |
 |_____/|_| |_|\\__,_|_|     |_|  |_|\\__,_|_|\\__,_|\\__,_| |____|(_)___/
  `)
  console.log(`${colors.reset}`)
  console.log(`${colors.bold}         Supply Chain Attack Scanner v1.0${colors.reset}`)
  console.log(`${colors.cyan}         Based on Socket.dev, Datadog, Wiz Research${colors.reset}`)
  console.log('')
}

// ============================================================================
// IOC Management
// ============================================================================

async function downloadIOCs(): Promise<IOCPackages> {
  log.header('Downloading Latest IOC List')

  return new Promise((resolve) => {
    https.get(CONFIG.iocUrl, (res) => {
      let data = ''
      res.on('data', (chunk: Buffer) => data += chunk)
      res.on('end', () => {
        const packages = parseIOCList(data)
        log.success(`Downloaded IOC list: ${Object.keys(packages).length} packages`)
        resolve(packages)
      })
    }).on('error', (err: Error) => {
      log.warning(`Could not download IOC list: ${err.message}`)
      log.info('Using embedded IOC list')
      resolve(getEmbeddedIOCs())
    })
  })
}

function parseIOCList(csvData: string): IOCPackages {
  const packages: IOCPackages = {}
  const lines = csvData.split('\n')

  for (const line of lines) {
    if (line.startsWith('package_name') || !line.trim())
      continue

    const [name, versions] = line.split(',')
    if (name && versions)
      packages[name.trim()] = versions.split('|').map(v => v.trim().replace(/"/g, ''))
  }

  return packages
}

function autoRegenerateIOCs(): void {
  // Get the directory where this file is located
  const srcDir = path.dirname(new URL(import.meta.url).pathname)
  const shaiTxtPath = path.join(srcDir, 'shai.txt')
  const iocPackagesPath = path.join(srcDir, 'ioc-packages.ts')

  // Check if shai.txt exists
  if (!fs.existsSync(shaiTxtPath)) {
    return // No source file, skip auto-regeneration
  }

  // Check if ioc-packages.ts exists or is outdated
  let shouldRegenerate = false

  if (!fs.existsSync(iocPackagesPath)) {
    shouldRegenerate = true
    log.info('IOC packages file not found, generating...')
  }
  else {
    const shaiStats = fs.statSync(shaiTxtPath)
    const iocStats = fs.statSync(iocPackagesPath)

    if (shaiStats.mtime > iocStats.mtime) {
      shouldRegenerate = true
      log.info('shai.txt has been updated, regenerating IOC packages...')
    }
  }

  if (shouldRegenerate) {
    try {
      const parsePath = path.join(srcDir, 'parse.ts')
      execSync(`bun ${parsePath}`, {
        cwd: srcDir,
        stdio: 'inherit',
      })
      log.success('IOC packages regenerated successfully')
    }
    catch (e) {
      log.warning('Failed to regenerate IOC packages, using existing data')
    }
  }
}

function getEmbeddedIOCs(): IOCPackages {
  // Try to load from generated file first
  try {
    const { iocPackages } = require('./ioc-packages')
    return iocPackages
  }
  catch {
    // Fallback to minimal list if generated file doesn't exist
    log.warning('IOC packages file not found, using minimal fallback list')
    return {
      '@accordproject/concerto-analysis': ['3.24.1'],
      '@accordproject/concerto-linter': ['3.24.1'],
    }
  }
}

// ============================================================================
// Package Scanning
// ============================================================================

function scanNodeModules(scanDir: string, iocPackages: IOCPackages): void {
  log.header('Scanning node_modules for Compromised Packages')

  const nodeModulesDirs = findDirectories(scanDir, 'node_modules')

  if (nodeModulesDirs.length === 0) {
    log.warning('No node_modules directories found')
    return
  }

  for (const nmDir of nodeModulesDirs) {
    log.info(`Scanning: ${nmDir}`)

    for (const [pkgName, compromisedVersions] of Object.entries(iocPackages)) {
      results.scannedPackages++

      const pkgPath = path.join(nmDir, pkgName)
      const pkgJsonPath = path.join(pkgPath, 'package.json')

      if (fs.existsSync(pkgJsonPath)) {
        try {
          const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'))
          const installedVersion = pkgJson.version

          if (compromisedVersions.includes(installedVersion)) {
            const finding: CompromisedPackage = {
              package: pkgName,
              version: installedVersion,
              location: pkgPath,
              severity: 'CRITICAL',
            }
            results.compromisedPackages.push(finding)
            log.error(`COMPROMISED: ${pkgName}@${installedVersion}`)
            log.error(`  Location: ${pkgPath}`)
          }
        }
        catch (e) {
          // Ignore parsing errors
        }
      }
    }
  }

  if (results.compromisedPackages.length === 0)
    log.success('No compromised packages found in node_modules')
}

function scanLockFiles(scanDir: string, iocPackages: IOCPackages): void {
  log.header('Scanning Lock Files')

  const lockFiles = [
    ...findFiles(scanDir, 'package-lock.json'),
    ...findFiles(scanDir, 'yarn.lock'),
    ...findFiles(scanDir, 'pnpm-lock.yaml'),
  ]

  for (const lockFile of lockFiles) {
    log.info(`Checking: ${lockFile}`)

    try {
      const content = fs.readFileSync(lockFile, 'utf8')

      for (const [pkgName, versions] of Object.entries(iocPackages)) {
        for (const version of versions) {
          // Check various lock file formats
          const patterns = [
            `"${pkgName}": "${version}"`,
            `${pkgName}@${version}`,
            `"version": "${version}"`,
          ]

          for (const pattern of patterns) {
            if (content.includes(pattern) && content.includes(pkgName)) {
              results.compromisedPackages.push({
                package: pkgName,
                version,
                location: lockFile,
                severity: 'CRITICAL',
                source: 'lockfile',
              })
              log.error(`Compromised package in lockfile: ${pkgName}@${version}`)
              break
            }
          }
        }
      }
    }
    catch (e) {
      log.warning(`Could not read lock file: ${lockFile}`)
    }
  }
}

// ============================================================================
// Malicious File Detection
// ============================================================================

function scanMaliciousFiles(scanDir: string): void {
  log.header('Scanning for Malicious Files')

  // Check for known malicious file names
  for (const fileName of CONFIG.maliciousFileNames) {
    const files = findFiles(scanDir, fileName)

    for (const file of files) {
      const hash = calculateSHA1(file)
      const finding: MaliciousFile = {
        file,
        sha1: hash,
        matched: CONFIG.maliciousFileHashes[hash] || 'Unknown variant',
        severity: 'CRITICAL',
      }

      results.maliciousFiles.push(finding)
      log.error(`Malicious file detected: ${file}`)

      if (CONFIG.maliciousFileHashes[hash])
        log.error(`  SHA-1 matches known malware: ${hash}`)
    }
  }

  // Check for large obfuscated JS files (Shai-Hulud payload is ~10MB)
  log.info('Checking for suspicious obfuscated files...')
  const jsFiles = findFiles(scanDir, '*.js', { maxDepth: 5 })

  for (const jsFile of jsFiles) {
    try {
      const stats = fs.statSync(jsFile)

      if (stats.size > 5 * 1024 * 1024) { // > 5MB
        const content = fs.readFileSync(jsFile, 'utf8').slice(0, 10000)

        // Check for obfuscation patterns
        if (/\\x[0-9a-f]{2}/i.test(content) || /atob\(|btoa\(/i.test(content)) {
          results.warnings.push({
            type: 'suspicious_file',
            file: jsFile,
            size: stats.size,
            reason: 'Large obfuscated JavaScript file',
          })
          log.warning(`Suspicious file: ${jsFile} (${(stats.size / 1024 / 1024).toFixed(2)} MB)`)
        }
      }
    }
    catch (e) {
      // Ignore read errors
    }
  }

  if (results.maliciousFiles.length === 0)
    log.success('No malicious files detected')
}

function scanSuspiciousScripts(scanDir: string): void {
  log.header('Scanning for Suspicious Scripts')

  const packageJsonFiles = findFiles(scanDir, 'package.json', { excludeNodeModules: true })

  for (const pkgFile of packageJsonFiles) {
    try {
      const content = fs.readFileSync(pkgFile, 'utf8')
      const pkg = JSON.parse(content)

      // Check preinstall/postinstall scripts
      const scriptsToCheck = ['preinstall', 'postinstall', 'prepare']

      for (const scriptName of scriptsToCheck) {
        const script = pkg.scripts?.[scriptName]

        if (script) {
          // Check for suspicious patterns
          const isSuspicious = CONFIG.maliciousFileNames.some(f => script.includes(f))
            || script.includes('bun') && script.includes('.js')
            || CONFIG.suspiciousPatterns.some(p => p.test(script))

          if (isSuspicious) {
            const finding: SuspiciousScript = {
              file: pkgFile,
              script: scriptName,
              command: script,
              severity: 'HIGH',
            }
            results.suspiciousScripts.push(finding)
            log.error(`Suspicious ${scriptName} script in: ${pkgFile}`)
            log.error(`  Command: ${script}`)
          }
        }
      }
    }
    catch (e) {
      // Ignore parsing errors
    }
  }

  if (results.suspiciousScripts.length === 0)
    log.success('No suspicious scripts found')
}

// ============================================================================
// GitHub Markers Detection
// ============================================================================

function scanGitHubMarkers(scanDir: string): void {
  log.header('Scanning for GitHub Infection Markers')

  const gitDir = path.join(scanDir, '.git')

  if (!fs.existsSync(gitDir)) {
    log.info('No .git directory found')
    return
  }

  // Check for suspicious branches
  try {
    const branches = execSync('git branch -a', { cwd: scanDir, encoding: 'utf8' })

    if (/shai-hulud/i.test(branches)) {
      const marker: GitHubMarker = {
        type: 'suspicious_branch',
        details: 'Branch containing "shai-hulud" detected',
        severity: 'CRITICAL',
      }
      results.githubMarkers.push(marker)
      log.error('Suspicious branch "shai-hulud" detected!')
    }
  }
  catch (e) {
    // Git command failed
  }

  // Check for suspicious commits
  try {
    const commits = execSync('git log --oneline -30', { cwd: scanDir, encoding: 'utf8' })

    for (const pattern of CONFIG.suspiciousPatterns) {
      if (pattern.test(commits)) {
        results.githubMarkers.push({
          type: 'suspicious_commit',
          details: `Commit message matching ${pattern}`,
          severity: 'HIGH',
        })
        log.error('Suspicious commit messages detected!')
        break
      }
    }
  }
  catch (e) {
    // Git command failed
  }

  // Check GitHub Actions workflows
  const workflowDir = path.join(scanDir, '.github', 'workflows')

  if (fs.existsSync(workflowDir)) {
    const workflows = fs.readdirSync(workflowDir).filter(f => f.endsWith('.yml') || f.endsWith('.yaml'))

    for (const workflow of workflows) {
      const workflowPath = path.join(workflowDir, workflow)

      try {
        const content = fs.readFileSync(workflowPath, 'utf8')

        for (const pattern of CONFIG.suspiciousPatterns) {
          if (pattern.test(content)) {
            results.githubMarkers.push({
              type: 'suspicious_workflow',
              file: workflowPath,
              pattern: pattern.toString(),
              severity: 'CRITICAL',
            })
            log.error(`Suspicious workflow: ${workflowPath}`)
            break
          }
        }

        // Check for discussion.yaml backdoor
        if (workflow.toLowerCase() === 'discussion.yaml' || workflow.toLowerCase() === 'discussion.yml') {
          if (content.includes('discussion') && content.includes('created')) {
            results.githubMarkers.push({
              type: 'backdoor_workflow',
              file: workflowPath,
              details: 'Potential Shai-Hulud backdoor workflow detected',
              severity: 'CRITICAL',
            })
            log.error(`Backdoor workflow detected: ${workflowPath}`)
          }
        }
      }
      catch (e) {
        // Ignore read errors
      }
    }
  }

  if (results.githubMarkers.length === 0)
    log.success('No GitHub infection markers found')
}

// ============================================================================
// Self-Hosted Runner Check
// ============================================================================

function scanRunners(): void {
  log.header('Checking for Malicious Self-Hosted Runners')

  const homeDir = process.env.HOME || process.env.USERPROFILE || ''
  const suspiciousRunnerPaths = [
    path.join(homeDir, '.dev-env'),
    path.join(homeDir, '.github-runner'),
  ]

  for (const runnerPath of suspiciousRunnerPaths) {
    if (fs.existsSync(runnerPath)) {
      results.githubMarkers.push({
        type: 'malicious_runner',
        path: runnerPath,
        details: 'Suspicious GitHub Actions runner directory',
        severity: 'CRITICAL',
      })
      log.error(`Malicious runner directory found: ${runnerPath}`)
    }
  }

  // Check for running SHA1HULUD process (Unix only)
  if (process.platform !== 'win32') {
    try {
      const processes = execSync('ps aux', { encoding: 'utf8' })
      if (/SHA1HULUD/i.test(processes)) {
        results.githubMarkers.push({
          type: 'malicious_process',
          details: 'SHA1HULUD runner process is running',
          severity: 'CRITICAL',
        })
        log.error('Malicious runner process "SHA1HULUD" is running!')
      }
    }
    catch (e) {
      // Process check failed
    }
  }

  if (!results.githubMarkers.some(m => m.type === 'malicious_runner' || m.type === 'malicious_process'))
    log.success('No malicious self-hosted runners detected')
}

// ============================================================================
// Utility Functions
// ============================================================================

function findDirectories(baseDir: string, name: string): string[] {
  const dirs: string[] = []

  function walk(dir: string, depth = 0): void {
    if (depth > 10)
      return // Prevent too deep recursion

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true })

      for (const entry of entries) {
        if (entry.isDirectory()) {
          if (entry.name === name)
            dirs.push(path.join(dir, entry.name))
          else if (entry.name !== 'node_modules' && !entry.name.startsWith('.'))
            walk(path.join(dir, entry.name), depth + 1)
        }
      }
    }
    catch (e) {
      // Ignore access errors
    }
  }

  walk(baseDir)
  return dirs
}

function findFiles(baseDir: string, pattern: string, options: FindFilesOptions = {}): string[] {
  const files: string[] = []
  const { maxDepth = 10, excludeNodeModules = false } = options

  function walk(dir: string, depth = 0): void {
    if (depth > maxDepth)
      return

    try {
      const entries = fs.readdirSync(dir, { withFileTypes: true })

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name)

        if (entry.isDirectory()) {
          if (excludeNodeModules && entry.name === 'node_modules')
            continue
          if (!entry.name.startsWith('.'))
            walk(fullPath, depth + 1)
        }
        else if (entry.isFile()) {
          if (pattern.includes('*')) {
            const regex = new RegExp(`^${pattern.replace('*', '.*')}$`)
            if (regex.test(entry.name))
              files.push(fullPath)
          }
          else if (entry.name === pattern) {
            files.push(fullPath)
          }
        }
      }
    }
    catch (e) {
      // Ignore access errors
    }
  }

  walk(baseDir)
  return files
}

function calculateSHA1(filePath: string): string {
  try {
    const content = fs.readFileSync(filePath)
    return crypto.createHash('sha1').update(content).digest('hex')
  }
  catch (e) {
    return 'unknown'
  }
}

// ============================================================================
// Report Generation
// ============================================================================

function generateReport(scanDir: string): number {
  log.header('Scan Summary')

  const duration = ((Date.now() - results.startTime) / 1000).toFixed(2)
  const totalIssues = results.compromisedPackages.length
    + results.maliciousFiles.length
    + results.suspiciousScripts.length
    + results.githubMarkers.length

  console.log('')
  console.log(`  ${colors.bold}Scan Directory:${colors.reset}  ${scanDir}`)
  console.log(`  ${colors.bold}Duration:${colors.reset}        ${duration}s`)
  console.log(`  ${colors.bold}Packages Checked:${colors.reset} ${results.scannedPackages}`)
  console.log('')
  console.log(`  ${colors.bold}Compromised Packages:${colors.reset} ${colors.red}${results.compromisedPackages.length}${colors.reset}`)
  console.log(`  ${colors.bold}Malicious Files:${colors.reset}      ${colors.red}${results.maliciousFiles.length}${colors.reset}`)
  console.log(`  ${colors.bold}Suspicious Scripts:${colors.reset}   ${colors.red}${results.suspiciousScripts.length}${colors.reset}`)
  console.log(`  ${colors.bold}GitHub Markers:${colors.reset}       ${colors.red}${results.githubMarkers.length}${colors.reset}`)
  console.log(`  ${colors.bold}Warnings:${colors.reset}             ${colors.yellow}${results.warnings.length}${colors.reset}`)
  console.log('')

  // Save JSON report
  const reportDir = path.join(process.cwd(), 'export-report')

  // Create export-report directory if it doesn't exist
  if (!fs.existsSync(reportDir)) {
    fs.mkdirSync(reportDir, { recursive: true })
  }

  const reportPath = path.join(reportDir, `shai-hulud-report-${Date.now()}.json`)
  const report = {
    scanDate: new Date().toISOString(),
    scanDirectory: scanDir,
    duration: `${duration}s`,
    summary: {
      totalIssues,
      compromisedPackages: results.compromisedPackages.length,
      maliciousFiles: results.maliciousFiles.length,
      suspiciousScripts: results.suspiciousScripts.length,
      githubMarkers: results.githubMarkers.length,
      warnings: results.warnings.length,
    },
    findings: {
      compromisedPackages: results.compromisedPackages,
      maliciousFiles: results.maliciousFiles,
      suspiciousScripts: results.suspiciousScripts,
      githubMarkers: results.githubMarkers,
      warnings: results.warnings,
    },
    recommendations: [
      'Remove compromised packages: rm -rf node_modules && npm cache clean --force',
      'Pin dependencies to versions before November 21, 2025',
      'Rotate all npm tokens, GitHub PATs, SSH keys, and cloud credentials',
      'Check GitHub for repos with "Sha1-Hulud" in description',
      'Review GitHub Actions workflows for unauthorized changes',
      'Enable phishing-resistant MFA for all developer accounts',
      'Use npm trusted publishing feature',
      'Disable lifecycle scripts in CI: --ignore-scripts',
    ],
  }

  fs.writeFileSync(reportPath, JSON.stringify(report, null, 2))
  log.success(`Report saved to: ${reportPath}`)

  // Print final status
  console.log('')
  if (totalIssues > 0) {
    console.log(`${colors.red}${colors.bold}⚠️  CRITICAL: Potential Shai-Hulud 2.0 compromise detected!${colors.reset}`)
    console.log('')
    console.log('Immediate Actions Required:')
    console.log('  1. Delete node_modules: rm -rf node_modules')
    console.log('  2. Clear npm cache: npm cache clean --force')
    console.log('  3. Rotate ALL credentials (npm, GitHub, AWS, GCP, Azure)')
    console.log('  4. Check GitHub for unauthorized repos')
    console.log('  5. Review CI/CD pipelines for unauthorized changes')
    console.log('')
    return 1
  }
  else if (results.warnings.length > 0) {
    console.log(`${colors.yellow}${colors.bold}⚡ Some warnings detected - review recommended${colors.reset}`)
    console.log('')
    return 0
  }
  else {
    console.log(`${colors.green}${colors.bold}✅ No Shai-Hulud 2.0 indicators detected${colors.reset}`)
    console.log('')
    console.log('Preventive Recommendations:')
    console.log('  • Use npm\'s trusted publishing feature')
    console.log('  • Enable phishing-resistant MFA')
    console.log('  • Disable lifecycle scripts in CI: --ignore-scripts')
    console.log('  • Pin dependencies to known safe versions')
    console.log('')
    return 0
  }
}

// ============================================================================
// Main Entry Point
// ============================================================================

async function main(): Promise<void> {
  printBanner()

  const scanDir = process.argv[2] || process.cwd()

  if (!fs.existsSync(scanDir)) {
    log.error(`Directory not found: ${scanDir}`)
    process.exit(1)
  }

  const absolutePath = path.resolve(scanDir)
  log.info(`Scanning directory: ${absolutePath}`)
  log.info(`Scan started at: ${new Date().toISOString()}`)

  // Auto-regenerate IOC packages if shai.txt is updated
  autoRegenerateIOCs()

  // Download IOCs
  const iocPackages = await downloadIOCs()

  // Run all scans
  scanNodeModules(absolutePath, iocPackages)
  scanLockFiles(absolutePath, iocPackages)
  scanMaliciousFiles(absolutePath)
  scanSuspiciousScripts(absolutePath)
  scanGitHubMarkers(absolutePath)
  scanRunners()

  // Generate report and exit
  const exitCode = generateReport(absolutePath)
  process.exit(exitCode)
}

// Run main
main().catch((err: Error) => {
  log.error(`Scanner error: ${err.message}`)
  process.exit(1)
})
