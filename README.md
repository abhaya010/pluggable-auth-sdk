# Pluggable Auth SDK

A modular, multi-tenant authentication service and SDK supporting OAuth2, Basic Auth, and Client Credentials with JWT tokens.

## Features

- Multi-tenant architecture
- Pluggable authentication strategies
- Google OAuth2 integration
- JWT token generation and validation
- Client SDK for easy integration
- RESTful API endpoints

## Quick Start

1. Install dependencies:
   ```bash
   npm install
   ```

2. Set up environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration (especially Google OAuth2 credentials)
   ```

3. Seed the database:
   ```bash
   npm run seed
   ```

4. Start the server:
   ```bash
   npm start
   ```

## API Endpoints

- `POST /login` - Basic authentication
- `POST /token` - Client credentials flow
- `GET /auth/google` - Google OAuth2 initiation
- `GET /auth/google/callback` - Google OAuth2 callback
- `GET /.well-known/jwks.json` - Public keys for JWT verification

## Testing

Run the OAuth2 integration test:
```bash
npm test
```

## Examples

See the `examples/` directory for usage examples.

