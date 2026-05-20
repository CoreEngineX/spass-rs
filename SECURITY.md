# Security Policy

## Reporting a vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Email **security@coreengine-x.com** with:
- A description of the vulnerability
- Steps to reproduce
- Impact assessment if known

You will receive a response within 72 hours. Please allow time for a fix to be prepared before public disclosure.

## Scope

This project processes encrypted password data locally. The attack surface includes:

- Incorrect decryption implementation (AES-256-CBC / PBKDF2)
- Memory exposure of sensitive data (passwords, derived keys)
- Path traversal or file handling issues in the CLI

## Known limitations

- CBC mode provides no authentication — constrained by the `.spass` format
- Decrypted data is not memory-locked; the OS may swap sensitive pages to disk
- The `-p` CLI flag exposes the password in the process list — prefer interactive prompting
