# ShaiScanner 2.0

ShaiScanner 2.0 is a Windows security scanner that checks installed packages and related files for known signs of the Shai-Hulud supply-chain worm.

It is intended to help identify affected packages before they can spread to other systems or expose additional credentials.

## Features

- Scans installed packages on selected drives
- Checks package names, versions, files, and known malicious hashes
- Uses multiple threat-intelligence sources
- Groups findings by severity
- Helps identify packages that may require further investigation
- Supports offline scans using cached threat data

## Important

A clean scan does **not** prove that the system was never affected.

ShaiScanner can only detect indicators that are currently included in its rules and threat-intelligence feeds. Some malicious files may have removed themselves, changed, or existed only during package installation.

A **CRITICAL** result means the scanner found an exact match for a known malicious file hash. Treat the system as potentially compromised and investigate it immediately.

## Usage
1. Download the latest release.
2. Run `ShaiHulud2Scanner.exe`.
3. Select the drives you want to scan.
4. Synchronize the threat-intelligence feeds when an internet connection is available.
5. Start the system scan.
6. Review all findings, including coverage issues, warnings, and files the scanner could not access.

## If a Critical Match Is Found
- Immediately disconnect the affected system from the internet and the rest of your environment.
- Remove the affected package or reinstall it from a trusted source.
- Rotate npm, cloud, SSH, CI/CD, and any other credentials that may have been exposed.
- Check the system for persistence, additional malware, or unauthorized changes.
- Do not reuse credentials that were present on the system during the suspected compromise.
- Review other systems that may have received packages, files, or credentials from the affected machine.

## Disclaimer
ShaiScanner 2.0 is provided for defensive security and incident-response use.

It does not remove said malware, repair affected packages, rotate credentials, or guarantee that a system is clean. 
### Always review the results carefully and follow your normal incident-response procedures.

## License

See the repository license for usage terms.
