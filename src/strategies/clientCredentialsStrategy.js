const Client = require("../models/client")
const Tenant = require("../models/tenant")

class ClientCredentialsStrategy {
  constructor() {
    this.name = "client_credentials"
  }

  async authenticate(credentials, tenantId) {
    try {
      const { client_id, client_secret } = credentials

      if (!client_id || !client_secret) {
        throw new Error("Client ID and client secret are required")
      }

      const client = await Client.findOne({
        clientId: client_id,
        tenantId,
        active: true,
      })

      if (!client) {
        throw new Error("Invalid client credentials")
      }

      if (client.clientSecret !== client_secret) {
        throw new Error("Invalid client credentials")
      }

      const tenant = await Tenant.findOne({ tenantId, active: true })
      if (!tenant) {
        throw new Error("Tenant not found or inactive")
      }

      return {
        subject: client.clientId,
        tenantId: tenant.tenantId,
        issuer: tenant.issuer,
        scopes: client.scopes || ["api:read"],
        audience: "api",
        client: {
          id: client._id,
          clientId: client.clientId,
          name: client.name,
        },
      }
    } catch (error) {
      throw new Error(`Client authentication failed: ${error.message}`)
    }
  }
}

module.exports = ClientCredentialsStrategy
