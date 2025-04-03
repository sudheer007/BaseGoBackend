# GoBackend Secure Multi-Tenant API

This repository contains a highly secure, multi-tenant REST API backend implemented in Go. It's designed for enterprise applications with a strong focus on security, performance, compliance, and maintainability.

**Target Repository:** This project is intended for `https://github.com/sudheer007/BaseGoBackend.git`.

## Core Implemented Capabilities

This backend provides a robust foundation with the following **implemented** features:

*   **Multi-Tenancy:** Foundational models for Tenants, Users, Organizations, etc. exist (`internal/models/`).
*   **Authentication (`internal/auth/service.go`):**
    *   Secure JWT-based authentication flow (using `github.com/golang-jwt/jwt/v5`).
    *   Refresh token mechanism.
    *   Password verification (likely Argon2id via `crypto.go`).
    *   Account locking after failed login attempts.
*   **Authorization (`internal/auth/rbac.go`):**
    *   Flexible Role-Based Access Control (RBAC) powered by `github.com/casbin/casbin/v2`.
    *   In-memory policy adapter (suitable for getting started, may need persistent adapter for production).
*   **Database:** PostgreSQL integration. *(Needs verification of ORM used, e.g., `go-pg`)*.
*   **Cryptography Service (`internal/security/crypto.go`):**
    *   AEAD Encryption: AES-GCM & ChaCha20-Poly1305.
    *   Password Hashing: Argon2id.
    *   Key Management: In-memory key storage with versioning and rotation support.
    *   Key Derivation: HKDF.
    *   HMAC for integrity.
    *   Serialization format for encrypted data including metadata.
*   **Secure Audit Logging (`internal/security/securitylogger.go`, `internal/middleware/audit.go`):**
    *   Tamper-evident logging using HMAC chaining and sequence numbers.
    *   Middleware to log all requests/responses with redaction of sensitive fields.
*   **Input Security Middleware (`internal/middleware/sanitize.go`):**
    *   Protection against XSS, SQL/NoSQL Injection, Path Traversal, Command Injection, XXE using `bluemonday`.
    *   Sanitizes query params, URL params, headers, JSON bodies, and form data.
*   **API Security Middleware (`internal/middleware/`):**
    *   **Rate Limiting (`ratelimit.go`):** Configurable multi-tier rate limiting (IP, User, Tenant, Global) using `golang.org/x/time/rate`.
    *   **Security Headers (`security_headers.go`):** Sets HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
    *   **CORS (`cors.go`):** Configurable Cross-Origin Resource Sharing.
*   **Data Governance & Compliance:**
    *   Data Classification & Retention system (`internal/data/classification.go`).
    *   User Consent Management system (`internal/consent/consent.go`).
    *   Documentation: DPIA, Secure Development Lifecycle, Vendor Security, Security Testing Plan, Configuration Guide (`docs/`).
*   **Key Management Service Interface (`internal/security/kms.go`):**
    *   Defines standard interface (`KMSClient`) for interacting with KMS.
    *   Includes a **local mock implementation** (`LocalKMSClient`) for development/testing.
*   **Error Handling:** Structured error handling framework.
*   **Configuration:** Centralized security constants (`internal/security/securityconstants.go`).

## Missing Features / Components Requiring Implementation

While the foundation is strong, key areas require further implementation for a production-ready system:

*   **Real KMS Integration:** Implement concrete clients in `internal/security/kms.go` for desired providers (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault) to replace the local mock.
*   **Multi-Factor Authentication (MFA):** The authentication service (`internal/auth/service.go`) has placeholders but needs integration with actual MFA methods (e.g., TOTP validation).
*   **Security Monitoring & Alerting:** The interfaces/structs exist (`internal/security/securitymonitoring.go`, `monitoring.go`), but the core logic for processing events and sending alerts needs implementation.
*   **Data Exfiltration Controls:** The concepts exist (`internal/security/exfiltration.go`), but active monitoring and prevention logic need implementation.
*   **Database Migrations:** Integrate and configure a migration tool (e.g., `golang-migrate`) to manage schema changes robustly.
*   **Persistent Casbin Adapter:** Replace the in-memory adapter in `internal/auth/rbac.go` with a persistent one (e.g., `gorm-adapter`, `pg-adapter`) if needed for scalability or policy persistence across restarts.
*   **Testing:** Significantly expand unit, integration, and security test coverage across all components.
*   **API Documentation:** Implement Swagger/OpenAPI generation (e.g., using `swaggo`).
*   **Deployment Artifacts:** Create Dockerfiles, Kubernetes manifests, or other deployment configurations.
*   **Performance Optimizations:** Implement caching (Redis), asynchronous task processing, query optimization based on profiling.
*   **Code Cleanup:** Deprecate/remove the older `internal/security/encryption.go` file in favor of `crypto.go`.

## Prerequisites

*   Go 1.21+ (Verify based on `go.mod`)
*   PostgreSQL 12+
*   Make (optional, for running commands in Makefile if created)

## Project Structure

```
.
├── cmd/
│   └── api/                 # API application entry point
├── docs/                    # Documentation (DPIA, Config Guides, etc.)
├── internal/                # Internal packages (business logic, data access, security)
│   ├── api/                 # API handlers and routes (if separated)
│   ├── auth/                # Authentication & Authorization logic (JWT, Casbin)
│   ├── consent/             # User consent management
│   ├── data/                # Data classification & retention
│   ├── database/            # Database connection, repositories
│   ├── middleware/          # HTTP middleware (Audit, CORS, RateLimit, Sanitize, Headers)
│   ├── models/              # Data structures/entities
│   ├── security/            # Core security services (Crypto, KMS, Logger, Monitor, Constants)
│   └── ...                  # Other internal domains
├── pkg/                     # Packages potentially reusable by external applications
├── .env.example             # Example environment variables
├── .gitignore               # Git ignore file
├── go.mod                   # Go module definition
├── go.sum                   # Go module checksums
└── README.md                # This file
```

## Getting Started (Local Development)

1.  **Clone the repository:**
    ```bash
    # Using HTTPS
    git clone https://github.com/sudheer007/BaseGoBackend.git
    # Or using SSH
    # git clone git@github.com:sudheer007/BaseGoBackend.git
    cd BaseGoBackend
    ```

2.  **Install Dependencies:**
    ```bash
    go mod tidy
    ```

3.  **Configuration:**
    *   Copy the example environment file:
        ```bash
        cp .env.example .env
        ```
    *   Edit the `.env` file with your local settings:
        *   Database credentials (`DB_...`).
        *   JWT secrets/keys.
        *   API port (`PORT`).
        *   Encryption keys (defaults might work initially with `crypto.go`).
        *   KMS settings (will use local mock by default).

4.  **Database Setup:**
    *   Ensure PostgreSQL is running.
    *   Create the database specified in `.env`.
    *   **Run Migrations:** *Determine the correct command or startup behavior for schema setup.* (e.g., `go run cmd/migrate/main.go` - **Needs confirmation**)

5.  **Run the API:**
    ```bash
    go run cmd/api/main.go
    ```
    Access via `http://localhost:PORT` (e.g., `http://localhost:8080`).

## Running on a Linux Server

1.  **Build the Binary:**
    ```bash
    # Ensure target OS/Arch are correct
    GOOS=linux GOARCH=amd64 go build -o gobackend_api cmd/api/main.go
    ```

2.  **Transfer Binary & Config:**
    *   Copy the `gobackend_api` executable to your server (e.g., `/opt/gobackend/`).
    *   Copy the configured `.env` file or set environment variables on the server.

3.  **Database:**
    *   Ensure DB is accessible.
    *   Run migrations if necessary.

4.  **Run the Application (using systemd recommended):**
    *   Create `/etc/systemd/system/gobackend.service` (see example in previous README version or below).
    *   Configure `User`, `Group`, `WorkingDirectory`, `ExecStart`, and `EnvironmentFile` (if using).
    *   Enable & Start: `sudo systemctl enable gobackend && sudo systemctl start gobackend`

    *Example `systemd` service file (`/etc/systemd/system/gobackend.service`):*
    ```ini
    [Unit]
    Description=GoBackend Secure API Service
    After=network.target postgresql.service
    Requires=postgresql.service

    [Service]
    User=gobackenduser      # Use a dedicated, non-root user
    Group=gobackendgroup
    WorkingDirectory=/opt/gobackend
    # If using .env file in WorkingDirectory, ensure app loads it.
    # Alternatively, use EnvironmentFile:
    # EnvironmentFile=/etc/gobackend/gobackend.conf
    ExecStart=/opt/gobackend/gobackend_api
    Restart=on-failure
    RestartSec=5s
    StandardOutput=journal
    StandardError=journal
    SyslogIdentifier=gobackend-api

    [Install]
    WantedBy=multi-user.target
    ```

## Security Considerations

*   **Configuration is Key:** Carefully review and set production values in `.env` or environment variables, especially for secrets (JWT, DB password, encryption keys).
*   **KMS:** For production, **implement and configure a real KMS provider** (AWS, GCP, Azure, Vault) in `internal/security/kms.go` and related configuration. Do not use the local mock.
*   **Key Rotation:** Implement regular key rotation for JWT signing keys and the master encryption keys used by the `CryptoService` (potentially managed via KMS).
*   **Secrets Management:** Use a secure system (like Vault, cloud provider secret managers) to inject secrets, not hardcoding or committing them.
*   **Firewalls:** Restrict network access to necessary ports.
*   **Dependencies:** Regularly update dependencies (`go get -u all`, `go mod tidy`) and scan for vulnerabilities.
*   **Testing:** Conduct regular security testing (SAST, DAST, Pen Testing).

## Compliance

*(Keep existing or update based on target regulations)*

Designed with GDPR, SOC 2 Type 2, ISO 27001 considerations. Ensure configurations (data retention, consent) meet specific requirements.

## License

*(Keep existing or update if needed)*

[MIT License](LICENSE)

## Contributing

*(Keep existing or update contribution guidelines)*

Contributions are welcome! Please feel free to submit a Pull Request.