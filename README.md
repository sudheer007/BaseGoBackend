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
*   Make (optional, for easier command execution)

## Project Structure

```
.                 # Project Root
├── cmd/
│   └── api/      # API application entry point (main.go)
├── docs/         # Documentation (DPIA, Config Guides, etc.)
├── internal/     # Internal packages (business logic, data access, security)
├── pkg/          # Packages potentially reusable by external applications
├── .env          # Local environment variables (DO NOT COMMIT)
├── .env.example  # Example environment variables (for reference)
├── .gitignore    # Git ignore file
├── go.mod        # Go module definition
├── go.sum        # Go module checksums
├── Makefile      # Build/Run/Test helper scripts
└── README.md     # This file
```

## Environment Configuration

Configuration is managed via environment variables. For local development, you can create a `.env` file in the project root.

1.  **Copy the example:**
    ```bash
    cp .env.example .env
    ```
2.  **Edit `.env`:** Update settings like database credentials, JWT secrets, etc. **Do not commit `.env` to version control.**

**Key Environment Variable: `APP_ENV`**

This variable controls the application's operating mode:

*   `APP_ENV=local`: (Default) For local development. Enables debug logging and other development aids.
*   `APP_ENV=development`: For staging or development servers.
*   `APP_ENV=production`: For production servers. Disables debug mode, uses info-level logging.

The application will automatically adjust `Debug` mode and `LogLevel` based on `APP_ENV`.

## Getting Started (Local Development)

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd <repository-directory>
    ```

2.  **Install Dependencies:**
    ```bash
    go mod tidy
    ```

3.  **Setup Configuration:**
    *   Copy `.env.example` to `.env`: `cp .env.example .env`
    *   Ensure `APP_ENV=local` is set in `.env`.
    *   Update database credentials (`DB_...`) and other secrets in `.env`.

4.  **Database Setup:**
    *   Ensure PostgreSQL is running.
    *   Create the database specified in `.env`.
    *   The application attempts to create the schema on startup (verify `db.CreateSchema()` in `main.go`).

5.  **Run the API:**
    *   **Using `make` (Recommended):**
        ```bash
        make run
        ```
    *   **Using `go run`:**
        ```bash
        go run cmd/api/main.go
        ```

Access the API at `http://localhost:PORT` (e.g., `http://localhost:8080`) and Swagger docs at `http://localhost:PORT/swagger/index.html`.

## Running on a Server (Production/Development Environment)

1.  **Build the Binary:**
    ```bash
    # Ensure target OS/Arch are correct if cross-compiling
    # GOOS=linux GOARCH=amd64 make build
    make build
    ```
    This creates an executable named `gobackend_api`.

2.  **Deploy:**
    *   Copy the `gobackend_api` executable to your server (e.g., `/opt/gobackend/`).

3.  **Configure Environment Variables:**
    *   **Crucially, set `APP_ENV=production` (or `development`)**. Never run with `APP_ENV=local` in production.
    *   Set all other required environment variables (DB host/pass, JWT secret, Redis host, etc.) directly on the server. **Do not rely on a `.env` file in production.** Use your deployment mechanism (systemd EnvironmentFile, Docker env vars, Kubernetes Secrets/ConfigMaps, etc.).

4.  **Database:**
    *   Ensure the database is accessible from the server.
    *   Ensure the schema is created/migrated (manual migration might be needed for production).

5.  **Run the Application (using systemd recommended):**
    *   Create a systemd service file (e.g., `/etc/systemd/system/gobackend.service`). Refer to the example in the previous README section or below.
    *   Ensure the service file sets the correct `APP_ENV` and other environment variables.
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
    # --- Environment Variables --- #
    Environment="APP_ENV=production"
    Environment="DB_HOST=your_prod_db_host"
    Environment="DB_PASS=your_prod_db_password"
    Environment="JWT_SECRET=your_strong_prod_jwt_secret"
    # ... add all other required environment variables ...
    # Alternatively, use EnvironmentFile=/etc/gobackend/gobackend.conf
    
    ExecStart=/opt/gobackend/gobackend_api
    Restart=on-failure
    RestartSec=5s
    StandardOutput=journal
    StandardError=journal
    SyslogIdentifier=gobackend-api

    [Install]
    WantedBy=multi-user.target
    ```

## Makefile Commands

```bash
# Run the API locally
make run

# Run all tests
make test

# Run tests with coverage analysis
make test-coverage

# Format code
make fmt

# Run linters
make lint

# Build the application (runs tests automatically)
make build

# Clean build artifacts
make clean

# Show all available commands
make help
```

## Testing

The project includes a comprehensive testing framework to ensure code quality and prevent regressions. For more information, see the [Testing Guidelines](docs/testing.md).

### Key Testing Features

- **Pre-Build Testing**: Tests are automatically run before each build.
- **Table-Driven Tests**: Tests use a table-driven approach for clear and comprehensive test cases.
- **Mocking**: Dependencies are mocked using the `testify/mock` package.
- **Coverage Reports**: Test coverage reports can be generated using `make test-coverage`.
- **CI Integration**: Tests are run automatically in CI environments using `make ci-test`.

To run tests:

```bash
# Run all tests
make test

# Run tests with coverage analysis
make test-coverage
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

## Third-Party Services Integration

This project includes integration with several third-party services for enhanced functionality.

### OpenRouter Integration

The OpenRouter API integration allows you to leverage powerful AI models for chat completions and other AI-related tasks.

#### Configuration

To configure OpenRouter, add the following environment variables:

```env
# OpenRouter configuration
OPENROUTER_ENABLED=true
OPENROUTER_API_KEY=your-openrouter-api-key-here
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_TIMEOUT_SECONDS=30
OPENROUTER_RETRY_ATTEMPTS=3
OPENROUTER_RETRY_WAIT_SECONDS=1
```

#### API Usage

Once configured, the OpenRouter API is available through the following endpoint:

```
POST /api/v1/ai/chat-completion
```

Request payload:

```json
{
  "model": "openai/gpt-3.5-turbo",
  "messages": [
    {
      "role": "system",
      "content": "You are a helpful assistant."
    },
    {
      "role": "user",
      "content": "Hello, who are you?"
    }
  ],
  "temperature": 0.7,
  "max_tokens": 150
}
```

Response:

```json
{
  "id": "response-id",
  "model": "openai/gpt-3.5-turbo",
  "content": "I am an AI assistant designed to help answer questions and provide information. How can I assist you today?"
}
```

For a full list of available models, refer to the [OpenRouter API documentation](https://openrouter.ai/docs).