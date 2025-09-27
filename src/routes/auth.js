const express = require("express")
const authController = require("../controller/authController")

const router = express.Router()

router.post("/login", authController.login.bind(authController))
router.post("/token", authController.token.bind(authController))
router.post("/:tenant/login", authController.login.bind(authController))
router.post("/:tenant/token", authController.token.bind(authController))

router.get("/auth/google", authController.googleAuth.bind(authController))
router.get("/auth/google/callback", authController.googleCallback.bind(authController))
router.get("/:tenant/auth/google", authController.googleAuth.bind(authController))
router.get("/:tenant/auth/google/callback", authController.googleCallback.bind(authController))

router.get("/:tenant/.well-known/jwks.json", authController.jwks.bind(authController))
router.get("/.well-known/jwks.json", authController.jwks.bind(authController))

router.get("/strategies", (req, res) => {
  const strategyFactory = require("../strategies/strategyFactory")
  res.json({
    available_strategies: strategyFactory.getAvailableStrategies(),
    description: "Available authentication strategies",
  })
})

router.get("/auth/health", (req, res) => {
  res.json({
    service: "auth",
    status: "healthy",
    timestamp: new Date().toISOString(),
    strategies: require("../strategies/strategyFactory").getAvailableStrategies(),
  })
})

module.exports = router
