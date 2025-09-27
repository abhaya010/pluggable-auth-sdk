const { jwtVerify, createRemoteJWKSet } = require("jose")
const Tenant = require("../models/tenant")

class JWTMiddleware {
  constructor() {
    this.jwksCache = new Map()
  }

  authenticate(options = {}) {
    return async (req, res, next) => {
      try {
        const token = this.extractToken(req)
        if (!token) {
          return res.status(401).json({
            error: "unauthorized",
            error_description: "Access token is required",
          })        }

        const payload = await this.verifyToken(token, req)

        req.user = {
          sub: payload.sub,
          tenantId: payload.tid,
          scopes: payload.scp || [],
          iss: payload.iss,
          aud: payload.aud,
          exp: payload.exp,
          iat: payload.iat,
        }

        if (options.requiredScopes) {
          const hasRequiredScope = options.requiredScopes.some((scope) => req.user.scopes.includes(scope))

          if (!hasRequiredScope) {
            return res.status(403).json({
              error: "insufficient_scope",
              error_description: `Required scopes: ${options.requiredScopes.join(", ")}`,
            })
          }
        }

        next()
      } catch (error) {
        console.error("JWT validation error:", error.message)
        res.status(401).json({
          error: "invalid_token",
          error_description: error.message,
        })
      }
    }
  }

  extractToken(req) {
    const authHeader = req.headers.authorization
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return null
    }
    return authHeader.substring(7)
  }

  async verifyToken(token, req) {
    const [header, payload] = token.split(".")
    const decodedPayload = JSON.parse(Buffer.from(payload, "base64url").toString())

    const tenantId = decodedPayload.tid || req.params.tenant || "default"

    const tenant = await Tenant.findOne({ tenantId, active: true })
    if (!tenant) {
      throw new Error("Invalid tenant")
    }

    const publicKey = await this.importPublicKey(tenant.publicKey)
    const { payload: verifiedPayload } = await jwtVerify(token, publicKey, {
      issuer: tenant.issuer,
      algorithms: ["RS256"],
    })

    return verifiedPayload
  }

  async importPublicKey(pemKey) {
    const { createPublicKey } = require("crypto")
    return createPublicKey(pemKey)
  }

  static extractClaims(req) {
    return req.user || null
  }
}

module.exports = new JWTMiddleware()
