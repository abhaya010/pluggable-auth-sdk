# Pluggable Auth SDK

A modular, multi-tenant authentication service and SDK supporting OAuth2, Basic Auth, and Client Credentials with JWT tokens.

## Features

- Multi-tenant architecture
- Pluggable authentication strategies (Basic Auth, OAuth2, Google OAuth2)
- JWT token generation and validation
- Client SDK for easy integration
- RESTful API endpoints
- MongoDB integration

## Quick Start

### Prerequisites
- Node.js >= 14.0.0
- MongoDB running locally or MongoDB Atlas

### Installation

```bash
# Clone and install
git clone https://github.com/abhaya010/pluggable-auth-sdk.git
cd pluggable-auth-sdk
npm install

# Setup environment (create .env file with your MongoDB URI and JWT secret)
# Start MongoDB if using local installation
sudo systemctl start mongod

# Seed database with sample data
npm run seed

# Start the server
npm start
```

Server runs on `http://localhost:3000`

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/login` | Basic authentication (username/password) |
| `POST` | `/token` | Client credentials OAuth2 flow |
| `GET` | `/auth/google` | Google OAuth2 authentication |
| `GET` | `/.well-known/jwks.json` | Public keys for JWT verification |

### Example Usage

```bash
# Basic login
curl -X POST http://localhost:3000/login \
  -H "Content-Type: application/json" \
  -d '{"username": "john.doe", "password": "password123", "tenantId": "tenant1"}'

# Client credentials
curl -X POST http://localhost:3000/token \
  -H "Content-Type: application/json" \
  -d '{"grant_type": "client_credentials", "client_id": "test-client", "client_secret": "test-secret", "tenantId": "tenant1"}'
```

## SDK Usage

```javascript
const ModularAuthSDK = require('./sdk');

const authSDK = new ModularAuthSDK({
  baseUrl: 'http://localhost:3000',
  tenantId: 'tenant1'
});

// Login with username/password
const result = await authSDK.login('john.doe', 'password123');
console.log('Access Token:', result.accessToken);
```

## Testing & Examples

```bash
# Run SDK demonstration
npm test

# Run individual examples
node examples/sdk-usage.js
node examples/google-oauth-demo.js
node examples/resource-server.js
```

## Default Test Data

After running `npm run seed`, you can use:
- **User**: `john.doe` / `password123`
- **Client**: `test-client` / `test-secret`
- **Tenant**: `tenant1`



