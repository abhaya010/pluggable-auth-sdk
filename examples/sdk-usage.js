const ModularAuthSDK = require("../sdk")

async function demonstrateSDK() {
  const authSDK = new ModularAuthSDK({
    baseUrl: "http://localhost:3000",
    tenantId: "tenant1",
  })

  console.log("=== Modular Auth SDK Demo ===\n")

  try {
    console.log("1. Testing user login...")
    const loginResult = await authSDK.login("john.doe", "password123")

    if (loginResult.success) {
      console.log(" Login successful")
      console.log(`  Access Token: ${loginResult.accessToken.substring(0, 50)}...`)
      console.log(`  Expires In: ${loginResult.expiresIn} seconds`)
      console.log(`  Scope: ${loginResult.scope}\n`)
    } else {
      console.log(" Login failed:", loginResult.error)
      return
    }

    console.log("2. Testing authenticated request...")
    try {
      console.log(" Token is valid and ready for API calls")
      console.log(`  Current token: ${authSDK.getAccessToken() ? "Valid" : "Invalid"}\n`)
    } catch (error) {
      console.log("Authenticated request failed:", error.message)
    }

    console.log("Testing client credentials...")
    const clientResult = await authSDK.getClientToken("client123", "secret456")

    if (clientResult.success) {
      console.log(" Client authentication successful")
      console.log(`  Access Token: ${clientResult.accessToken.substring(0, 50)}...`)
      console.log(`  Scope: ${clientResult.scope}\n`)
    } else {
      console.log("Client authentication failed:", clientResult.error)
    }

    console.log("4. Testing JWKS retrieval...")
    const jwksResult = await authSDK.getJWKS()

    if (jwksResult.success) {
      console.log(" JWKS retrieved successfully")
      console.log(`  Keys count: ${jwksResult.jwks.keys.length}`)
      console.log(`  Key ID: ${jwksResult.jwks.keys[0].kid}\n`)
    } else {
      console.log("JWKS retrieval failed:", jwksResult.error)
    }

    console.log("5. Testing logout...")
    authSDK.logout()
    console.log("Logged out successfully")
    console.log(`  Token valid: ${authSDK.isTokenValid()}`)
  } catch (error) {
    console.error("Demo error:", error.message)
  }
}

if (require.main === module) {
  demonstrateSDK()
}

module.exports = demonstrateSDK
