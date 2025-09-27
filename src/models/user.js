const mongoose = require("mongoose")
const bcrypt = require("bcryptjs")

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      index: true,
    },
    email: {
      type: String,
      required: true,
    },
    passwordHash: {
      type: String,
      required: function() {
        return !this.googleId && !this.authProvider
      },
    },
    tenantId: {
      type: String,
      required: true,
      index: true,
    },
    scopes: [
      {
        type: String,
      },
    ],
    active: {
      type: Boolean,
      default: true,
    },
    // OAuth2 fields
    googleId: {
      type: String,
      index: true,
      sparse: true,
    },
    authProvider: {
      type: String,
      enum: ["local", "google"],
      default: "local",
    },
    profile: {
      name: String,
      picture: String,
      locale: String,
      verified_email: Boolean,
    },
  },
  {
    timestamps: true,
  },
)

userSchema.index({ tenantId: 1, username: 1 }, { unique: true })
userSchema.index({ tenantId: 1, email: 1 })
userSchema.index({ tenantId: 1, googleId: 1 }, { unique: true, sparse: true })

userSchema.pre("save", async function (next) {
  if (!this.isModified("passwordHash") || !this.passwordHash) return next()
  this.passwordHash = await bcrypt.hash(this.passwordHash, 12)
  next()
})

userSchema.methods.comparePassword = async function (password) {
  if (!this.passwordHash) return false
  return bcrypt.compare(password, this.passwordHash)
}

module.exports = mongoose.model("User", userSchema)
