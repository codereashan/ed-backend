import mongoose, { Schema } from "mongoose";
import jwt from "jsonwebtoken";
import bcrypt from "bcrypt"

const userSchema = new Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    index: true
  },
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
  },
  fullName: {
    type: String,
    required: true,
    trim: true,
    index: true
  },
  avatar: {
    type: String,   // cloudinary url
    required: true,
  },
  coverImage: {
    type: String,   // cloudinary url
  },
  watchHistory: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Video",
    }
  ],
  password: {
    type: String,
    required: [true, 'Password is required'],
  },
  refreshToken: {
    type: String,
  },
}, { timestamps: true })

// pre middleware used since we are hashing password just before save
// we cant use arrow function below since it doesnt contain reference of this, no context
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next()  // isModified can be used to check which data is modified

  this.password = await bcrypt.hash(this.password, 10)
  next()
})

// method to check if password is correct
userSchema.methods.isPasswordCorrect = async function (password) {
  return await bcrypt.compare(password, this.password)
}

// method to generate access token
userSchema.methods.generateAccessToken = function () {
  return jwt.sign(
    {
      _id: this._id,
      email: this.email,
      username: this.username,
      fullName: this.fullName
    },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: process.env.ACCESS_TOKEN_EXPIRY }
  )
}

// method to generate refresh token
userSchema.methods.generateRefreshToken = function () {
  return jwt.sign(
    { _id: this._id },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: process.env.REFRESH_TOKEN_EXPIRY }
  )
}

export const User = mongoose.model("User", userSchema)