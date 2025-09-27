const BasicAuthStrategy = require("./basicAuthStrategy")
const ClientCredentialsStrategy = require("./clientCredentialsStrategy")
const GoogleOAuth2Strategy = require("./googleOAuth2Strategy")

class StrategyFactory {
  constructor() {
    this.strategies = new Map()
    this.registerDefaultStrategies()
  }

  registerDefaultStrategies() {
    this.register(new BasicAuthStrategy())
    this.register(new ClientCredentialsStrategy())
    this.register(new GoogleOAuth2Strategy())
  }

  register(strategy) {
    if (!strategy.name || typeof strategy.authenticate !== "function") {
      throw new Error("Invalid strategy: must have name and authenticate method")
    }
    this.strategies.set(strategy.name, strategy)
  }

  getStrategy(name) {
    const strategy = this.strategies.get(name)
    if (!strategy) {
      throw new Error(`Strategy '${name}' not found`)
    }
    return strategy
  }

  getAvailableStrategies() {
    return Array.from(this.strategies.keys())
  }
}

module.exports = new StrategyFactory()
