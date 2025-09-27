const mongoose = require("mongoose")
const { generateKeyPair, exportPKCS8, exportSPKI } = require("jose")
require("dotenv").config()

const Tenant = require("../src/models/tenant")
const Client = require("../src/models/client")
const User = require("../src/models/user")

async function generateTenantKeys() {
  const { privateKey, publicKey } = await generateKeyPair("RS256")
  const privateKeyPem = await exportPKCS8(privateKey)
  const publicKeyPem = await exportSPKI(publicKey)

  return { privateKeyPem, publicKeyPem }
}

async function seedDatabase() {
  try {
    await mongoose.connect(process.env.MONGODB_URI || "mongodb://localhost:27017/modular-auth")
    console.log("Connected to MongoDB for seeding")

    await Promise.all([Tenant.deleteMany({}), Client.deleteMany({}), User.deleteMany({})])
    console.log("Cleared existing data")

    const { privateKeyPem, publicKeyPem } = await generateTenantKeys()

    const tenant = await Tenant.create({
      tenantId: "tenant1",
      name: "Default Tenant",
      issuer: "https://auth.example.com",
      privateKey: privateKeyPem,
      publicKey: publicKeyPem,
      keyId: "default-key-1",
      active: true,
    })
    console.log("Created tenant:", tenant.tenantId)

    const client = await Client.create({
      clientId: "client123",
      clientSecret: "secret456",
      tenantId: "tenant1",
      name: "Sample API Client",
      scopes: ["api:read", "api:write", "user:profile"],
      active: true,
    })
    console.log("Created client:", client.clientId)

    const user = await User.create({
      username: "john.doe",
      email: "john.doe@example.com",
      passwordHash: "password123",
      tenantId: "tenant1",
      scopes: ["read", "write", "profile"],
      active: true,
    })
    console.log("Created user:", user.username)

    const { privateKeyPem: privateKey2, publicKeyPem: publicKey2 } = await generateTenantKeys()

    const tenant2 = await Tenant.create({
      tenantId: "tenant2",
      name: "Second Tenant",
      issuer: "https://auth2.example.com",
      privateKey: privateKey2,
      publicKey: publicKey2,
      keyId: "tenant2-key-1",
      active: true,
    })
    console.log("Created second tenant:", tenant2.tenantId)

    await Client.create({
      clientId: "client789",
      clientSecret: "secret999",
      tenantId: "tenant2",
      name: "Tenant 2 Client",
      scopes: ["api:read"],
      active: true,
    })

    await User.create({
      username: "jane.smith",
      email: "jane.smith@example.com",
      passwordHash: "password456",
      tenantId: "tenant2",
      scopes: ["read"],
      active: true,
    })

    console.log("Database seeded successfully!")
    console.log("\nSample credentials:")
    console.log("Tenant 1:")
    console.log("  User: john.doe / password123")
    console.log("  Client: client123 / secret456")
    console.log("Tenant 2:")
    console.log("  User: jane.smith / password456")
    console.log("  Client: client789 / secret999")
  } catch (error) {
    console.error("Seeding error:", error)
  } finally {
    await mongoose.disconnect()
    console.log("Disconnected from MongoDB")
  }
}

if (require.main === module) {
  seedDatabase()
}

module.exports = seedDatabase
