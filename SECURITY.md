# Security Policy

Report vulnerabilities through GitHub private vulnerability reporting rather than a public issue. Use synthetic test data only.

Never commit provider keys, system prompts, customer data, raw production conversations, or generated artifacts containing sensitive information. Generated reports and audit logs are ignored by default.

The demo identity fields are not authentication. Deploying this outside localhost requires an IdP, RBAC, TLS, strict CORS/CSP, encrypted storage, rate limiting, target allowlisting, and controlled artifact retention.
