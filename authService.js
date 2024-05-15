const { generateToken, verifyToken } = require("./utils/jwt")
const { hashPassword, comparePassword } = require("./utils/bcrypt")

class AuthService {
  constructor(usermodel, jwtSecret, jwtExpiry, env) {
    this.User = usermodel
    this.jwtSecret = jwtSecret
    this.env = env || "development"
    this.jwtExpiry = jwtExpiry || "30d"
  }

  //LOGIN
  async login(req, res, next) {
    const { email, password } = req.body
    if (!email || !password) {
      return res.status(400, {
        status: "failed",
        message: "Please provide required credentials."
      })
    }
    const user = await this.User.findOne({ email }).select("+password")

    if (!user || !(await comparePassword(password, user.password))) {
      return res.status(401, {
        status: "failed",
        message: "Incorrect email or password."
      })
    }

    user.password = undefined
    const token = generateToken({
      id: user._id,
      secret: this.jwtSecret,
      expiresIn: "24h"
    })

    return res
      .cookie("jwt", token, {
        httpOnly: true,
        secure: this.env === "production",
        sameSite: "none",
        withCredentials: true
      })
      .status(200)
      .json({
        status: "success",
        message: "Logged in successfully",
        data: { user }
      })
  }

  //SIGNUP
  async signUp(req, res, next) {
    const { confirmPassword, password, email } = req.body
    const user = await User.findOne({ email })
    if (user) {
      return res.status(400, {
        status: "failed",
        message: "Email is already registered."
      })
    }
    if (password !== confirmPassword) {
      return res.status(400, {
        status: "failed",
        message: "Password and confirm password do not match."
      })
    }
    req.body.comparePassword = undefined
    req.body.password = await hashPassword(password, 12)
    const newUser = await User.create(req.body)
    const token = generateToken({
      id: newUser._id,
      secret: this.jwtSecret,
      expiresIn: "24h"
    })
    res.cookie("jwt", token, {
      httpOnly: true,
      secure: this.env === "production",
      sameSite: "none",
      withCredentials: true
    })
    res.status(201).json({
      status: "success",
      message: "New user created successfull",
      data: {
        user: newUser
      }
    })
  }

  //LOGOUT
  logout(req, res) {
    res.cookie("jwt", "")
    res.json({ status: "success", message: "Logged out successfully" })
  }

  //ISAUTHENTICATED
  async isAuthenticated(req, res, next) {
    let decoded
    const token = req.cookies.jwt
    if (!token)
      return res
        .status(401)
        .json({ status: "failed", message: "Token not present" })
    try {
      decoded = verifyToken(token, this.jwtSecret)
    } catch (error) {
      if (error.name === "TokenExpiredError") {
        res.status(401).json({
          status: "failed",
          message: "Token exipred! Please log in again"
        })
      }

      if (error.name === "JsonWebTokenError") {
        res.status(401).json({
          status: "failed",
          message: "Invalid token! Please log in again"
        })
      }
    }
    const user = await this.User.findById(decoded.id)
    if (!user) {
      return res
        .status(401)
        .json({ status: "failed", message: "User not found" })
    }
    req.user = user
    return next()
  }

  //ISAUTHORIZED
  isAuthorized(...roles) {
    return (req, res, next) => {
      if (roles.includes(req.user.role)) {
        next()
      } else {
        res.json({
          message: "You are not authorized"
        })
      }
    }
  }
}

module.exports = AuthService
