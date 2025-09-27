const express = require("express")
const ModularAuthSDK = require("../sdk")

const app = express()
const PORT = 3001

// Initialize the auth SDK
const authSDK = new ModularAuthSDK({
  baseUrl: "http://localhost:3000",
  tenantId: "tenant1",
})

app.use(express.json())

// Home page with login options
app.get("/", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>Google OAuth2 Demo</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
            .button { display: inline-block; padding: 12px 24px; margin: 10px 5px; text-decoration: none; 
                     background-color: #4285f4; color: white; border-radius: 4px; border: none; cursor: pointer; }
            .google-btn { background-color: #db4437; }
            .basic-btn { background-color: #34a853; }
            .result { margin-top: 20px; padding: 20px; background-color: #f5f5f5; border-radius: 4px; }
        </style>
    </head>
    <body>
        <h1>Modular Auth Demo</h1>
        <h2>Choose Authentication Method:</h2>
        
        <div>
            <a href="/auth/basic" class="button basic-btn">Basic Auth Login</a>
            <a href="/auth/google" class="button google-btn">Login with Google</a>
        </div>
        
        <div>
            <h3>Available Endpoints:</h3>
            <ul>
                <li><a href="/auth/basic">/auth/basic</a> - Test basic authentication</li>
                <li><a href="/auth/google">/auth/google</a> - Initiate Google OAuth2 flow</li>
                <li><a href="/auth/success">/auth/success</a> - OAuth2 success callback</li>
                <li><a href="/protected">/protected</a> - Test protected endpoint</li>
            </ul>
        </div>
    </body>
    </html>
  `)
})

// Basic auth demo
app.get("/auth/basic", async (req, res) => {
  try {
    const result = await authSDK.login("john.doe", "password123")
    
    if (result.success) {
      res.send(`
        <h2>Basic Auth Success!</h2>
        <div class="result">
          <p><strong>Access Token:</strong> ${result.accessToken.substring(0, 50)}...</p>
          <p><strong>Token Type:</strong> ${result.tokenType}</p>
          <p><strong>Expires In:</strong> ${result.expiresIn} seconds</p>
          <p><strong>Scope:</strong> ${result.scope}</p>
        </div>
        <a href="/">Back to Home</a>
      `)
    } else {
      res.send(`<h2>Basic Auth Failed</h2><p>Error: ${result.error}</p><a href="/">Back to Home</a>`)
    }
  } catch (error) {
    res.send(`<h2>Error</h2><p>${error.message}</p><a href="/">Back to Home</a>`)
  }
})

// Initiate Google OAuth2 flow
app.get("/auth/google", async (req, res) => {
  try {
    const result = await authSDK.getGoogleAuthUrl("http://localhost:3001/auth/success", "demo-state")
    
    if (result.success) {
      // Redirect to Google OAuth
      res.redirect(result.authUrl)
    } else {
      res.send(`<h2>Error</h2><p>${result.error}</p><a href="/">Back to Home</a>`)
    }
  } catch (error) {
    res.send(`<h2>Error</h2><p>${error.message}</p><a href="/">Back to Home</a>`)
  }
})

// OAuth2 success callback
app.get("/auth/success", (req, res) => {
  const { token, expires_in, error } = req.query
  
  if (error) {
    return res.send(`
      <h2>Authentication Failed</h2>
      <p>Error: ${error}</p>
      <a href="/">Back to Home</a>
    `)
  }
  
  if (token) {
    res.send(`
      <h2>Google OAuth2 Success!</h2>
      <div class="result">
        <p><strong>Access Token:</strong> ${token.substring(0, 50)}...</p>
        <p><strong>Expires In:</strong> ${expires_in} seconds</p>
        <p><strong>Provider:</strong> Google</p>
      </div>
      <div>
        <a href="/protected?token=${encodeURIComponent(token)}">Test Protected Endpoint</a> |
        <a href="/">Back to Home</a>
      </div>
    `)
  } else {
    res.send(`<h2>No token received</h2><a href="/">Back to Home</a>`)
  }
})

// OAuth2 error callback
app.get("/auth/error", (req, res) => {
  const { error, error_description } = req.query
  res.send(`
    <h2>Authentication Error</h2>
    <p><strong>Error:</strong> ${error}</p>
    <p><strong>Description:</strong> ${error_description}</p>
    <a href="/">Back to Home</a>
  `)
})

// Test protected endpoint
app.get("/protected", async (req, res) => {
  const { token } = req.query
  
  if (!token) {
    return res.send(`
      <h2>Protected Endpoint</h2>
      <p>No token provided. Please authenticate first.</p>
      <a href="/">Back to Home</a>
    `)
  }
  
  try {
    // Set the token in SDK
    authSDK.accessToken = token
    authSDK.tokenExpiry = Date.now() + 3600000 // 1 hour from now
    
    // Make authenticated request to resource server
    const response = await authSDK.makeAuthenticatedRequest("GET", "/auth/health")
    
    res.send(`
      <h2>Protected Endpoint Success!</h2>
      <div class="result">
        <p><strong>Response:</strong></p>
        <pre>${JSON.stringify(response, null, 2)}</pre>
      </div>
      <a href="/">Back to Home</a>
    `)
  } catch (error) {
    res.send(`
      <h2>Protected Endpoint Failed</h2>
      <p>Error: ${error.message}</p>
      <a href="/">Back to Home</a>
    `)
  }
})

app.listen(PORT, () => {
  console.log(`Demo app running on http://localhost:${PORT}`)
 
})

module.exports = app
