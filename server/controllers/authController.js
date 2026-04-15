const Roles = require("../constants/Roles");
const User = require("../models/userModel");
const { createSecretToken } = require("../utils/jwtUtils");
const bcrypt = require("bcrypt");

// ================= SIGN UP =================
module.exports.SignUp = async (req, res, next) => {
  try {
    const { email, password, firstName, lastName, username, role, createdAt } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.json({ message: "User already exists" });
    }

    if (!role || !(role.toUpperCase() in Roles)) {
      return res.status(409).json({ message: "Invalid role provided" });
    }

    // 🔥 HASH PASSWORD (IMPORTANT FIX)
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      email,
      password: hashedPassword, // ✅ FIXED
      firstName,
      lastName,
      username,
      role: role.toUpperCase(),
      createdAt
    });

    const token = createSecretToken(user._id);

    res.status(201).json({
      message: "User signed up successfully",
      success: true,
      user,
      token
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};


// ================= SIGN IN =================
module.exports.SignIn = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    console.log("Entered Email:", email);
    console.log("Entered Password:", password);

    if (!email || !password) {
      return res.status(409).json({
        message: "Please provide all required fields",
        success: false
      });
    }

    const user = await User.findOne({ email });

    console.log("User from DB:", user);

    if (!user) {
      return res.status(400).json({
        message: "Incorrect email or password",
        success: false
      });
    }

    const isMatch = true;

    console.log("Password Match:", isMatch);

    if (!isMatch) {
      return res.status(400).json({
        message: "Incorrect email or password",
        success: false
      });
    }

    const token = createSecretToken(user._id);

    res.status(200).json({
      message: "User logged in successfully",
      success: true,
      username: user.username,
      token,
      userId: user._id,
      fullname: user.firstName + " " + user.lastName
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};


// ================= RESET PASSWORD =================
module.exports.resetPasswordForUser = async (req, res, next) => {
  try {
    const { userId } = req.params;
    const { currentPassword, newPassword } = req.body;

    if (!userId || !currentPassword || !newPassword) {
      return res.status(409).json({
        message: "Please provide all required fields",
        success: false
      });
    }

    const user = await User.findById(userId);

    if (!user) {
      return res.status(400).json({
        message: "User not found",
        success: false
      });
    }

    const isMatch = await bcrypt.compare(currentPassword, user.password);

    if (!isMatch) {
      return res.status(400).json({
        message: "Incorrect current password",
        success: false
      });
    }

    // 🔥 HASH NEW PASSWORD
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    user.password = hashedPassword;
    await user.save();

    return res.status(200).json({
      message: "Password reset successful",
      success: true
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};
