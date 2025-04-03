# GoBackend Secure API: Security Configuration Guide

This document provides detailed information about the security components included in the GoBackend Secure API and how to configure them properly for production environments.

## Table of Contents

1. [Introduction](#introduction)
2. [Security Components Overview](#security-components-overview)
3. [Authentication Configuration](#authentication-configuration)
4. [Authorization and RBAC Configuration](#authorization-and-rbac-configuration)
5. [Encryption and Cryptography Settings](#encryption-and-cryptography-settings)
6. [Audit and Logging](#audit-and-logging)
7. [Input Sanitization](#input-sanitization)
8. [Rate Limiting](#rate-limiting)
9. [Data Protection Measures](#data-protection-measures)
10. [Security Headers Configuration](#security-headers-configuration)
11. [Monitoring and Alerting](#monitoring-and-alerting)
12. [Key Management](#key-management)
13. [Vulnerability Management](#vulnerability-management)
14. [Secure Development Practices](#secure-development-practices)
15. [Compliance Considerations](#compliance-considerations)

## Introduction

The GoBackend Secure API has been designed with security as a top priority. This guide will help you configure the various security components to meet enterprise-grade security requirements and comply with common security standards and regulations.

## Security Components Overview

The GoBackend Secure API includes the following security components:

- **Authentication System**: JWT-based authentication with support for multi-factor authentication.
- **Authorization System**: Role-based access control (RBAC) using Casbin.
- **Encryption**: AES-GCM and ChaCha20-Poly1305 encryption for sensitive data.
- **Audit Logging**: Tamper-evident security logging system.
- **Input Sanitization**: Protection against XSS, SQL injection, and other common attacks.
- **Rate Limiting**: Multi-tier rate limiting to prevent abuse.
- **Data Classification**: Data labeling and handling based on sensitivity.
- **Content Security Policy**: Configurable CSP headers.
- **Security Monitoring**: Real-time security event monitoring and alerting.
- **Key Management**: Key rotation and secure key storage.

## Authentication Configuration

### JWT Settings

Configure JWT authentication in `config/security.yaml`:

```yaml
authentication:
  jwt:
    signing_algorithm: "ES256" # Recommended: ES256, RS256, EdDSA
    token_lifetime: 15m # Short-lived tokens are more secure
    refresh_token_lifetime: 7d
    issuer: "gobackend-api"
    audience: "secure-app"
    private_key_path: "/path/to/private/key.pem" # Use environment-specific paths
```

For production, you should:

1. Use asymmetric signing algorithms (ES256, RS256, EdDSA)
2. Keep token lifetimes short (15 minutes or less)
3. Store private keys securely using a proper key management system
4. Rotate keys regularly (at least every 90 days)

### Multi-Factor Authentication

Enable MFA in `config/security.yaml`:

```yaml
authentication:
  mfa:
    enabled: true
    required_for_admin: true # Force MFA for administrative users
    methods:
      - totp # Time-based One-Time Password
      - backup_codes
    issuer: "GoBackend API" # For TOTP apps display
```

## Authorization and RBAC Configuration

The Role-Based Access Control system uses Casbin policies defined in `config/rbac_model.conf` and `config/rbac_policy.csv`.

### RBAC Model

Here's the recommended model configuration:

```
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _, _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && (r.obj == p.obj || keyMatch(r.obj, p.obj)) && (r.act == p.act || p.act == "*")
```

This model supports:
- Multi-tenancy (domain-aware policies)
- Role hierarchies
- Path-based pattern matching for resources

### Default Roles Configuration

Configure default roles in the system:

1. **System Administrator**: Full access to all resources
2. **Tenant Administrator**: Full access to tenant resources
3. **User Administrator**: Manage users and permissions
4. **Auditor**: Read-only access to logs and audit data
5. **Regular User**: Basic access to application features

## Encryption and Cryptography Settings

Configure encryption settings in `config/security.yaml`:

```yaml
encryption:
  default_algorithm: "AES-GCM"
  key_rotation:
    enabled: true
    interval_days: 90
  
  # Recommended ciphers for different sensitivity levels
  data_classification:
    public: "AES-GCM" # 256-bit
    internal: "AES-GCM" # 256-bit
    confidential: "ChaCha20-Poly1305"
    restricted: "ChaCha20-Poly1305"
```

### Encryption Implementation

The system uses a cryptography service that supports:

1. Encryption with authenticated encryption with associated data (AEAD)
2. Key versioning and rotation
3. Secure key derivation with Argon2id for password-based keys
4. HMAC authentication

For production, you should:
1. Store master keys in a hardware security module (HSM) or secure key management service
2. Enable automatic key rotation
3. Use different encryption keys for different purposes and data classifications

## Audit and Logging

Configure audit logging in `config/security.yaml`:

```yaml
audit:
  enabled: true
  log_requests: true
  log_responses: true
  tamper_proof: true
  log_level: "INFO" # DEBUG, INFO, WARNING, ERROR, CRITICAL
  storage:
    type: "database" # database, file, syslog
    retention_days: 365
  excluded_paths:
    - "/health"
    - "/metrics"
```

### Security Event Categories

The following events are audited:

1. Authentication events (login, logout, failed attempts)
2. Authorization events (access denied, privilege escalation)
3. Configuration changes
4. Data access/modification for sensitive information
5. Security setting changes
6. Administrative actions

### Log Format

Security logs include:
- Timestamp (ISO 8601 format with timezone)
- Event ID (unique identifier)
- Event category and type
- Severity level
- User information (ID, IP address, user agent)
- Action details
- Resource information
- Success/failure status
- Cryptographic hash for tamper detection

## Input Sanitization

Configure input sanitization in `config/security.yaml`:

```yaml
sanitization:
  enabled: true
  strict_mode: false # Reject suspicious input instead of sanitizing
  protections:
    xss: true
    sql_injection: true
    nosql_injection: true
    path_traversal: true
    command_injection: true
    xxe: true
  max_body_size: 10485760 # 10MB
```

This middleware sanitizes:
- Query parameters
- URL path parameters
- Headers
- Request bodies (JSON, form data)

## Rate Limiting

Configure rate limiting in `config/security.yaml`:

```yaml
rate_limiting:
  enabled: true
  strategy: "token_bucket" # token_bucket, fixed_window, sliding_window, adaptive
  
  global:
    requests_per_second: 1000
    burst: 1200
  
  ip:
    requests_per_second: 20
    burst: 50
  
  user:
    requests_per_second: 10
    burst: 30
  
  tenant:
    requests_per_second: 100
    burst: 200
  
  endpoints:
    "/api/v1/auth/login":
      requests_per_minute: 5
      burst: 10
```

Different limits should be applied based on the endpoint's sensitivity:

1. **Public endpoints**: Higher limits
2. **Authentication endpoints**: Lower limits to prevent brute force
3. **Resource-intensive endpoints**: Lower limits
4. **Critical business operations**: Lower limits with stricter monitoring

## Data Protection Measures

Configure data protection in `config/security.yaml`:

```yaml
data_protection:
  classification:
    enabled: true
    default: "internal"
  
  retention:
    enabled: true
    policies:
      logs: "1 year"
      personal_data: "5 years"
      financial_data: "7 years"
      temporary_data: "24 hours"
  
  masking:
    enabled: true
    patterns:
      - field: "credit_card"
        pattern: "XXXX-XXXX-XXXX-{last4}"
      - field: "email"
        pattern: "{first3}***@{domain}"
```

## Security Headers Configuration

Configure security headers in `config/security.yaml`:

```yaml
security_headers:
  content_security_policy: "default-src 'self'; script-src 'self' https://trusted-cdn.com; img-src 'self' data:; style-src 'self' https://trusted-cdn.com;"
  strict_transport_security: "max-age=31536000; includeSubDomains; preload"
  x_content_type_options: "nosniff"
  x_frame_options: "DENY"
  x_xss_protection: "1; mode=block"
  referrer_policy: "strict-origin-when-cross-origin"
  permissions_policy: "camera=(), microphone=(), geolocation=()"
```

## Monitoring and Alerting

Configure security monitoring in `config/security.yaml`:

```yaml
monitoring:
  enabled: true
  alert_channels:
    - email
    - slack
    - pagerduty
  
  alert_levels:
    critical:
      channels: ["email", "slack", "pagerduty"]
      threshold: 1 # Alert after 1 occurrence
    high:
      channels: ["email", "slack"]
      threshold: 3 # Alert after 3 occurrences
    medium:
      channels: ["slack"]
      threshold: 5
    low:
      channels: ["slack"]
      threshold: 10
  
  alert_rules:
    - name: "Brute Force Detection"
      description: "Multiple failed login attempts"
      severity: "high"
      condition: "count(failed_login) > 5 within 5m by ip"
    
    - name: "Privilege Escalation"
      description: "User gained admin privileges"
      severity: "critical"
      condition: "event = 'role_change' AND new_role = 'admin'"
```

## Key Management

### Key Rotation Schedule

Configure automatic key rotation:

```yaml
key_management:
  rotation:
    jwt_signing_keys: "90 days"
    encryption_keys: "90 days"
    hmac_keys: "180 days"
  
  storage:
    type: "vault" # vault, aws-kms, file
    path: "secret/gobackend/keys"
```

### Key Types and Usage

1. **Authentication Keys**: Used for JWT signing
2. **Encryption Keys**: Used for data encryption
3. **HMAC Keys**: Used for data integrity verification
4. **TLS Keys**: Used for HTTPS connections

## Vulnerability Management

Configure vulnerability scanning:

```yaml
vulnerability_management:
  dependency_scanning:
    enabled: true
    schedule: "daily"
    fail_on: "high" # Block builds with high vulnerabilities
  
  secret_scanning:
    enabled: true
    patterns:
      - name: "AWS Key"
        regex: "AKIA[0-9A-Z]{16}"
      - name: "API Key"
        regex: "key-[0-9a-zA-Z]{32}"
  
  dynamic_scanning:
    enabled: true
    schedule: "weekly"
    target: "https://staging-api.example.com"
```

## Secure Development Practices

Guidelines for secure development:

1. **Input Validation**: All user input must be validated
2. **Output Encoding**: All output must be properly encoded
3. **Authentication**: All endpoints must require authentication unless explicitly public
4. **Authorization**: All resources must have proper access controls
5. **Error Handling**: No sensitive information in error messages
6. **Logging**: No sensitive data in logs
7. **Security Testing**: Required before release

## Compliance Considerations

Configure compliance settings based on applicable regulations:

```yaml
compliance:
  frameworks:
    - name: "GDPR"
      enabled: true
      data_retention: "5 years"
      right_to_be_forgotten: true
    
    - name: "PCI-DSS"
      enabled: true
      mask_card_numbers: true
      encryption_required: true
    
    - name: "HIPAA"
      enabled: false
      phi_protection: true
      audit_trail: true
```

## Conclusion

This configuration guide provides a comprehensive overview of the security features available in the GoBackend Secure API. By properly configuring these components, you can create a secure, compliant, and robust application.

Remember to:
1. Use different configurations for different environments
2. Regularly audit and review your security settings
3. Keep dependencies up to date
4. Conduct regular security testing
5. Monitor for security events and respond appropriately 