const https = require("https")
const http = require("http")
const { URL } = require("url")

class ModularAuthSDK {
  constructor(options = {}) {
    this.baseUrl = options.baseUrl || "http://localhost:3000"
    this.tenantId = options.tenantId || "tenant1"
    this.timeout = options.timeout || 5000
    this.accessToken = null
    this.refreshToken = null
    this.tokenExpiry = null
  }

  async login(username, password) {
    try {
      const response = await this.makeRequest("POST", "/login", {
        username,
        password,
        tenant_id: this.tenantId,
      })

      this.accessToken = response.access_token
      this.tokenExpiry = Date.now() + response.expires_in * 1000

      return {
        success: true,
        accessToken: response.access_token,
        tokenType: response.token_type,
        expiresIn: response.expires_in,
        scope: response.scope,
      }
    } catch (error) {
      return {
        success: false,
        error: error.message,
      }
    }
  }

  async getClientToken(clientId, clientSecret) {
    try {
      const response = await this.makeRequest("POST", "/token", {
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret,
        tenant_id: this.tenantId,
      })

      this.accessToken = response.access_token
      this.tokenExpiry = Date.now() + response.expires_in * 1000

      return {
        success: true,
        accessToken: response.access_token,
        tokenType: response.token_type,
        expiresIn: response.expires_in,
        scope: response.scope,
      }
    } catch (error) {
      return {
        success: false,
        error: error.message,
      }
    }
  }

  async makeAuthenticatedRequest(method, url, data = null, options = {}) {
    // Auto-refresh if token is expired but refresh token exists
    if (!this.isTokenValid() && this.refreshToken) {
      const refreshResult = await this.refreshAccessToken()
      if (!refreshResult.success) {
        throw new Error("Failed to refresh token: " + refreshResult.error)
      }
    }

    if (!this.isTokenValid()) {
      throw new Error("No valid access token. Please authenticate first.")
    }

    const headers = {
      Authorization: `Bearer ${this.accessToken}`,
      ...options.headers,
    }

    return this.makeRequest(method, url, data, { ...options, headers })
  }

  async getJWKS() {
    try {
      const response = await this.makeRequest("GET", `/${this.tenantId}/.well-known/jwks.json`)
      return {
        success: true,
        jwks: response,
      }
    } catch (error) {
      return {
        success: false,
        error: error.message,
      }
    }
  }

  isTokenValid() {
    return this.accessToken && this.tokenExpiry && Date.now() < this.tokenExpiry
  }

  getAccessToken() {
    return this.isTokenValid() ? this.accessToken : null
  }

  logout() {
    this.accessToken = null
    this.refreshToken = null
    this.tokenExpiry = null
  }

  async refreshAccessToken() {
    try {
      if (!this.refreshToken) {
        throw new Error("No refresh token available")
      }

      const response = await this.makeRequest("POST", "/refresh", {
        refresh_token: this.refreshToken,
        tenant_id: this.tenantId,
      })

      this.accessToken = response.access_token
      this.tokenExpiry = Date.now() + response.expires_in * 1000

      return {
        success: true,
        accessToken: response.access_token,
        tokenType: response.token_type,
        expiresIn: response.expires_in,
        scope: response.scope,
      }
    } catch (error) {
      // If refresh fails, clear tokens
      this.logout()
      return {
        success: false,
        error: error.message,
      }
    }
  }

  async getGoogleAuthUrl(redirectUri, state) {
    try {
      const url = new URL(`/${this.tenantId}/auth/google`, this.baseUrl)
      if (redirectUri) url.searchParams.set("redirect_uri", redirectUri)
      if (state) url.searchParams.set("state", state)
      
      return {
        success: true,
        authUrl: url.toString(),
        message: "Redirect user to this URL for Google authentication"
      }
    } catch (error) {
      return {
        success: false,
        error: error.message,
      }
    }
  }

  async handleGoogleCallback(code, state) {
    try {
      const response = await this.makeRequest("GET", `/${this.tenantId}/auth/google/callback`, null, {
        headers: {
          "Accept": "application/json"
        },
        query: { code, state }
      })

      this.accessToken = response.access_token
      this.tokenExpiry = Date.now() + response.expires_in * 1000

      return {
        success: true,
        accessToken: response.access_token,
        tokenType: response.token_type,
        expiresIn: response.expires_in,
        scope: response.scope,
        user: response.user,
        authProvider: response.auth_provider
      }
    } catch (error) {
      return {
        success: false,
        error: error.message,
      }
    }
  }

  async makeRequest(method, path, data = null, options = {}) {
    return new Promise((resolve, reject) => {
      let url = new URL(path, this.baseUrl)
      
      if (options.query) {
        Object.entries(options.query).forEach(([key, value]) => {
          url.searchParams.set(key, value)
        })
      }
      
      const isHttps = url.protocol === "https:"
      const client = isHttps ? https : http

      const requestOptions = {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method: method.toUpperCase(),
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "ModularAuthSDK/1.0.0",
          ...options.headers,
        },
        timeout: this.timeout,
      }

      const req = client.request(requestOptions, (res) => {
        let body = ""
        res.on("data", (chunk) => (body += chunk))
        res.on("end", () => {
          try {
            const response = JSON.parse(body)
            if (res.statusCode >= 200 && res.statusCode < 300) {
              resolve(response)
            } else {
              reject(new Error(response.error_description || response.error || "Request failed"))
            }
          } catch (error) {
            reject(new Error("Invalid JSON response"))
          }
        })
      })

      req.on("error", reject)
      req.on("timeout", () => {
        req.destroy()
        reject(new Error("Request timeout"))
      })

      if (data && (method.toUpperCase() === "POST" || method.toUpperCase() === "PUT")) {
        req.write(JSON.stringify(data))
      }

      req.end()
    })
  }
}

module.exports = ModularAuthSDK
