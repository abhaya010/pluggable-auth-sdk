const express = require("express")
const jwtMiddleware = require("../src/middleware/jwtMiddleware")

const app = express()
app.use(express.json())

app.get("/public", (req, res) => {
  res.json({ message: "This is a public endpoint" })
})

app.get("/protected", jwtMiddleware.authenticate(), (req, res) => {
  res.json({
    message: "This is a protected endpoint",
    user: req.user,
    timestamp: new Date().toISOString(),
  })
})

app.get(
  "/admin",
  jwtMiddleware.authenticate({
    requiredScopes: ["admin", "write"],
  }),
  (req, res) => {
    res.json({
      message: "This is an admin endpoint",
      user: req.user,
      scopes: req.user.scopes,
    })
  },
)

app.get(
  "/profile",
  jwtMiddleware.authenticate({
    requiredScopes: ["profile", "read"],
  }),
  (req, res) => {
    res.json({
      message: "User profile data",
      userId: req.user.sub,
      tenant: req.user.tenantId,
      scopes: req.user.scopes,
    })
  },
)

const PORT = process.env.RESOURCE_PORT || 3001
app.listen(PORT, () => {
  console.log(`Resource server running on port ${PORT}`)
})

module.exports = app
