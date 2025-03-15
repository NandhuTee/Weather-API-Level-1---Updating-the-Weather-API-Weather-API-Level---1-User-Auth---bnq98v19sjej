const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const signup = async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate required fields
    if (!username || !email || !password) {
      return res.status(400).json({ message: "Please provide all required information", status: "Error" });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists", status: "Error" });
    }

    // Create new user
    const newUser = new User({ username, email, password });
    await newUser.save();

   res.status(201).json({
  status: "Success",  // ✅ Add this field
  message: "User created successfully",
  data: {
    user: {
      _id: newUser._id,
      username: newUser.username,
      email: newUser.email,
      password: newUser.password, // Hashed
        },
      },
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", status: "Error", error: error.message });
  }
};

const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ message: "Please provide email and password", status: "Error" });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ error: "Invalid credentials",  message: "Invalid email or password", status: "Error" });
    }

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Invalid credentials",  message: "Invalid email or password", status: "Error" });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username, email: user.email },
      process.env.TOKEN_SECRET,
      { expiresIn: "1h" }
    );

    res.status(200).json({ token, status: "Success" });
  } catch (error) {
    res.status(500).json({ message: "Server error", status: "Error", error: error.message });
  }
};

const decodeToken = (req, res) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      return res.status(401).json({ message: "No token provided", status: "Error" });
    }

    const decoded = jwt.verify(token, process.env.TOKEN_SECRET);
    res.status(200).json({ decoded, status: "Success" });
  } catch (error) {
    res.status(401).json({ message: "Invalid token", status: "Error" });
  }
};

module.exports = { signup, login, decodeToken };
