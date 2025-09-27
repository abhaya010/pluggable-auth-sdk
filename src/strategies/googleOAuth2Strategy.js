const { google } = require("googleapis")
const User = require("../models/user")
const Tenant = require("../models/tenant")

class GoogleOAuth2Strategy {
  constructor() {
    this.name = "google_oauth2"
    this.oauthClients = new Map()
  }

  getOAuth2Client(tenantId) {
    if (!this.oauthClients.has(tenantId)) {
      const oauth2Client = new google.auth.OAuth2(
        process.env.GOOGLE_CLIENT_ID,
        process.env.GOOGLE_CLIENT_SECRET,
        `${process.env.BASE_URL || "http://localhost:3000"}/auth/google/callback`
      )
      this.oauthClients.set(tenantId, oauth2Client)
    }
    return this.oauthClients.get(tenantId)
  }

  generateAuthUrl(tenantId, state) {
    const oauth2Client = this.getOAuth2Client(tenantId)
    
    return oauth2Client.generateAuthUrl({
      access_type: "offline",
      scope: ["profile", "email"],
      state: state,
      prompt: "consent"
    })
  }

  async authenticate(credentials, tenantId) {
    try {
      const { code } = credentials

      if (!code) {
        throw new Error("Authorization code is required")
      }

      const oauth2Client = this.getOAuth2Client(tenantId)
      const { tokens } = await oauth2Client.getToken(code)
      oauth2Client.setCredentials(tokens)

      const oauth2 = google.oauth2({ version: "v2", auth: oauth2Client })
      const { data: profile } = await oauth2.userinfo.get()

      if (!profile.email || !profile.verified_email) {
        throw new Error("Email verification required")
      }

      let user = await User.findOne({
        $or: [
          { email: profile.email, tenantId },
          { googleId: profile.id, tenantId }
        ],
        active: true,
      })

      if (!user) {
        user = await User.create({
          username: profile.email,
          email: profile.email,
          googleId: profile.id,
          tenantId,
          profile: {
            name: profile.name,
            picture: profile.picture,
            locale: profile.locale,
            verified_email: profile.verified_email
          },
          scopes: ["read", "profile"],
          active: true,
          authProvider: "google"
        })
      } else {
        user.profile = {
          name: profile.name,
          picture: profile.picture,
          locale: profile.locale,
          verified_email: profile.verified_email
        }
        user.googleId = profile.id
        await user.save()
      }

      const tenant = await Tenant.findOne({ tenantId, active: true })
      if (!tenant) {
        throw new Error("Tenant not found or inactive")
      }

      return {
        subject: user._id.toString(),
        tenantId: tenant.tenantId,
        issuer: tenant.issuer,
        scopes: user.scopes || ["read", "profile"],
        audience: "api",
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          googleId: user.googleId,
          profile: user.profile
        },
        authProvider: "google"
      }
    } catch (error) {
      throw new Error(`Google OAuth authentication failed: ${error.message}`)
    }
  }

  async initiateAuth(tenantId, redirectUri, state) {
    try {
      const tenant = await Tenant.findOne({ tenantId, active: true })
      if (!tenant) {
        throw new Error("Tenant not found or inactive")
      }

      const secureState = JSON.stringify({
        tenantId,
        state,
        timestamp: Date.now()
      })

      const authUrl = this.generateAuthUrl(tenantId, Buffer.from(secureState).toString("base64"))
      
      return {
        authUrl,
        state: secureState
      }
    } catch (error) {
      throw new Error(`Failed to initiate Google OAuth: ${error.message}`)
    }
  }

  validateState(stateParam, expectedTenantId) {
    try {
      const decoded = JSON.parse(Buffer.from(stateParam, "base64").toString())
      
      const maxAge = 10 * 60 * 1000
      if (Date.now() - decoded.timestamp > maxAge) {
        throw new Error("State parameter expired")
      }

      if (decoded.tenantId !== expectedTenantId) {
        throw new Error("Invalid tenant in state parameter")
      }

      return decoded
    } catch (error) {
      throw new Error("Invalid state parameter")
    }
  }
}

module.exports = GoogleOAuth2Strategy
