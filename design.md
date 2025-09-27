# Pluggable Auth SDK — Design Notes


---

## What I have implemented so far

### 1. Auth Service (in `src/`)
- A simple **Express.js HTTP service**.  
- Supports:
  - **Basic login** (`/login`): validates username/password from MongoDB and issues a signed JWT.  
  - **OAuth2/OIDC with Google** (`/auth/google`): redirects user to Google, handles callback, then issues a **first-party JWT** from my service.  
  - **Client Credentials** (`/token` with `grant_type=client_credentials`): service-to-service token flow.  
- Issues **JWTs** signed with a locally managed secret (HS256 for now).  
- Exposes a **JWKS endpoint** (`/.well-known/jwks.json`) so that other services can validate tokens.

### 2. SDK (in `sdk/`)
- Provides **middleware for Express** that:
  - Extracts Bearer tokens from requests.
  - Fetches and caches the JWKS from the auth service.
  - Verifies JWTs and attaches the payload to `req.user`.  
- Provides helper functions for:
  - **Login** (basic, OIDC).
  - **Token refresh** (basic support).
  - **Client credentials flow**.

### 3. Examples (in `examples/`)
- **Google OAuth demo**: shows how to log in with Google → then receive a **JWT from my service**.  
- **Resource server demo**: shows how to protect APIs using the SDK middleware.  
- **SDK usage demo**: small example of using login helpers.

### 4. Storage
- I used **MongoDB** for storing users and client configs.  
- Very minimal: just enough for login and token issuance.

---

## What this MVP proves
- I can wrap multiple login strategies (basic + OIDC) behind one service.  
- I can issue **first-party JWTs** consistently, no matter the source of authentication.  
- I can provide a **client SDK** that makes it easier for apps/APIs to integrate with the auth service.  
- Multi-tenant awareness is there in design (each tenant can have its own config/issuer), but right now I only tested with a single tenant setup.

---

## Limitations (what’s missing)
- **Security hardening**:  
  - Currently keys are just local secrets, not in KMS/Vault.  
  - No proper refresh token rotation (just stubbed).  
  - No rate limiting or brute-force protection yet.  
- **Tenant isolation**:  
  - The code is written with tenants in mind, but not fully fleshed out (e.g., no admin API to provision tenants).  
- **Authorization**:  
  - Only authentication is done. No roles/permissions engine.  
- **Production features**:  
  - No logging/metrics/audit trails.  
  - No key rotation.  
  - No MFA or WebAuthn (though I know how I’d plug it in).

---

## My Plan (next steps if I continue)
1. **Key Management & Security**
   - Move signing keys to KMS or Vault.  
   - Implement key rotation + per-tenant JWKS.  
   - Add refresh token rotation and replay detection.

2. **Multi-Tenant Support**
   - Add an **admin API** to create/manage tenants.  
   - Each tenant should have its own issuer, JWKS endpoint, and config (redirect URIs, token lifetimes).  

3. **Better SDK**
   - Add auto-refresh handling in the SDK.  
   - Provide utilities for cookies/CSRF.  
   - Improve tenant resolution (from request host/path).  

4. **Observability**
   - Add logging hooks for issued/revoked tokens.  
   - Add metrics (failed logins, token counts).  

5. **Future features**
   - Add MFA / WebAuthn support (pluggable interface).  
   - Add role-based access control (optional plugin).  
   - More identity provider connectors (GitHub, SAML).  

---

## How to read this project
- Start with `src/index.js`: see the Express auth service.  
- Then check `sdk/index.js`: see the middleware and helpers.  
- Finally, run the `examples/*` to see how it all ties together