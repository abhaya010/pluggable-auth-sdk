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
      required: true,
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
  },
  {
    timestamps: true,
  },
)

userSchema.index({ tenantId: 1, username: 1 }, { unique: true })

userSchema.pre("save", async function (next) {
  if (!this.isModified("passwordHash")) return next()
  this.passwordHash = await bcrypt.hash(this.passwordHash, 12)
  next()
})

userSchema.methods.comparePassword = async function (password) {
  return bcrypt.compare(password, this.passwordHash)
}

module.exports = mongoose.model("User", userSchema)
