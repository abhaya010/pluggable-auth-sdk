const { SignJWT, generateKeyPair, exportJWK } = require("jose")
const strategyFactory = require("../strategies/strategyFactory")
const Tenant = require("../models/tenant")

class AuthController {
  constructor() {
    this.jwtExpiry = process.env.JWT_EXPIRY || "3600"
  }

  async login(req, res) {
    try {
      const { username, password, tenant_id } = req.body
      const tenantId = tenant_id || req.params.tenant || "default"

      if (!username || !password) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "Username and password are required",
        })
      }

      const strategy = strategyFactory.getStrategy("basic")
      const authResult = await strategy.authenticate({ username, password }, tenantId)
      const token = await this.generateJWT(authResult, tenantId)

      res.json({
        access_token: token,
        token_type: "Bearer",
        expires_in: Number.parseInt(this.jwtExpiry),
        scope: authResult.scopes.join(" "),
      })
    } catch (error) {
      console.error("Login error:", error.message)
      res.status(401).json({
        error: "invalid_grant",
        error_description: error.message,
      })
    }
  }

  async token(req, res) {
    try {
      const { grant_type, client_id, client_secret, tenant_id } = req.body
      const tenantId = tenant_id || req.params.tenant || "default"

      if (grant_type !== "client_credentials") {
        return res.status(400).json({
          error: "unsupported_grant_type",
          error_description: "Only client_credentials grant type is supported",
        })
      }

      if (!client_id || !client_secret) {
        return res.status(400).json({
          error: "invalid_request",
          error_description: "Client ID and client secret are required",
        })
      }

      const strategy = strategyFactory.getStrategy("client_credentials")
      const authResult = await strategy.authenticate({ client_id, client_secret }, tenantId)
      const token = await this.generateJWT(authResult, tenantId)

      res.json({
        access_token: token,
        token_type: "Bearer",
        expires_in: Number.parseInt(this.jwtExpiry),
        scope: authResult.scopes.join(" "),
      })
    } catch (error) {
      console.error("Token error:", error.message)
      res.status(401).json({
        error: "invalid_client",
        error_description: error.message,
      })
    }
  }

  async jwks(req, res) {
    try {
      const tenantId = req.params.tenant || "default"

      const tenant = await Tenant.findOne({ tenantId, active: true })
      if (!tenant) {
        return res.status(404).json({
          error: "tenant_not_found",
          error_description: "Tenant not found or inactive",
        })
      }

      const publicKeyJWK = await exportJWK(await this.importPublicKey(tenant.publicKey))

      const jwks = {
        keys: [
          {
            ...publicKeyJWK,
            kid: tenant.keyId,
            alg: "RS256",
            use: "sig",
          },
        ],
      }

      res.json(jwks)
    } catch (error) {
      console.error("JWKS error:", error.message)
      res.status(500).json({
        error: "server_error",
        error_description: "Failed to retrieve public keys",
      })
    }
  }

  async generateJWT(authResult, tenantId) {
    const tenant = await Tenant.findOne({ tenantId, active: true })
    if (!tenant) {
      throw new Error("Tenant not found")
    }

    const privateKey = await this.importPrivateKey(tenant.privateKey)
    const now = Math.floor(Date.now() / 1000)

    return await new SignJWT({
      sub: authResult.subject,
      aud: authResult.audience,
      tid: authResult.tenantId,
      scp: authResult.scopes,
    })
      .setProtectedHeader({ alg: "RS256", kid: tenant.keyId })
      .setIssuer(authResult.issuer)
      .setIssuedAt(now)
      .setExpirationTime(now + Number.parseInt(this.jwtExpiry))
      .sign(privateKey)
  }

  async importPrivateKey(pemKey) {
    const { createPrivateKey } = require("crypto")
    return createPrivateKey(pemKey)
  }

  async importPublicKey(pemKey) {
    const { createPublicKey } = require("crypto")
    return createPublicKey(pemKey)
  }
}

module.exports = new AuthController()
