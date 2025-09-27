const User = require("../models/user")
const Tenant = require("../models/tenant")

class BasicAuthStrategy {
  constructor() {
    this.name = "basic"
  }

  async authenticate(credentials, tenantId) {
    try {
      const { username, password } = credentials

      if (!username || !password) {
        throw new Error("Username and password are required")
      }

      const user = await User.findOne({
        username,
        tenantId,
        active: true,
      })

      if (!user) {
        throw new Error("Invalid credentials")
      }

      const isValidPassword = await user.comparePassword(password)
      if (!isValidPassword) {
        throw new Error("Invalid credentials")
      }

      const tenant = await Tenant.findOne({ tenantId, active: true })
      if (!tenant) {
        throw new Error("Tenant not found or inactive")
      }

      return {
        subject: user._id.toString(),
        tenantId: tenant.tenantId,
        issuer: tenant.issuer,
        scopes: user.scopes || ["read"],
        audience: "api",
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
        },
      }
    } catch (error) {
      throw new Error(`Authentication failed: ${error.message}`)
    }
  }
}

module.exports = BasicAuthStrategy
