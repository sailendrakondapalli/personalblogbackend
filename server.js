// server.js
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const multer = require("multer");
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const cloudinary = require("cloudinary").v2;
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");

const app = express();
app.use(express.json());
app.use(cors());

// --- MongoDB connection ---
mongoose.connect(
  "mongodb+srv://sailendrakondapalli:personalblog@cluster0.wa8zmjw.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
)
  .then(() => console.log("MongoDB connected"))
  .catch(err => console.error("MongoDB connection error:", err));

// --- Schemas ---
const UserSchema = new mongoose.Schema({
  name: String,
  username: String, // email
  password: String,
  role: { type: String, default: "user" }, // default = user
});
const User = mongoose.model("User", UserSchema);

const ArticleSchema = new mongoose.Schema({
  title: String,
  description: String,
  image: String,
  date: { type: Date, default: Date.now },
  author: String,
  likes: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  comments: [
    {
      user: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      text: String,
      date: { type: Date, default: Date.now },
    },
  ],
});
const Article = mongoose.model("Article", ArticleSchema);

// --- Cloudinary config ---
cloudinary.config({
  cloud_name: "dgji6lwc9",
  api_key: "991287451317225",
  api_secret: "U6_VNnwk3i6EgQ1EKsxEZhQ0k44",
});

// --- Multer storage ---
const storage = new CloudinaryStorage({
  cloudinary,
  params: { folder: "articles", allowed_formats: ["jpg", "png", "jpeg"] },
});
const upload = multer({ storage });

// --- JWT verification middleware ---
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "No token provided" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ message: "No token provided" });

  try {
    const decoded = jwt.verify(token, "secretkey");
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid token" });
  }
};

// --- Nodemailer ---
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "sailendrakondapalli@gmail.com", // your Gmail
    pass: "napaiwxrhxjbsqnn", // ⚠️ use Gmail App Password
  },
});

// --- OTP store ---
const otps = {};

// --- Admin OTP Routes ---

// Send OTP (always to fixed admin email)
app.post("/auth/send-otp", async (req, res) => {
  try {
    const { email,name } = req.body;
    
    const exists = await User.findOne({ username: email });
    if (exists) return res.status(400).json({ message: "Admin already exists" });

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otps[email] = otp;

    await transporter.sendMail({
      from: "sailendrakondapalli@gmail.com",
      to: "sailendrakondapalli@gmail.com", // always send to fixed email
      subject: "Admin Account OTP Verification",
      text: `Hi Gowtham, ${name} is Request to create admin for: ${email}\nOTP: ${otp}`,
    });

    res.json({ success: true, message: "OTP sent to Super Admin email for approval" });
  } catch (err) {
    console.error("OTP Error:", err);
    res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});

// Verify OTP & create Admin
app.post("/auth/verify-otp", async (req, res) => {
  try {
    const { name, email, password, otp } = req.body;

    if (otps[email] !== otp) {
      return res.status(400).json({ success: false, message: "Invalid OTP" });
    }

    delete otps[email];

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = new User({ name, username: email, password: hashedPassword, role: "admin" });
    await user.save();

    const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, "secretkey");

    res.json({ success: true, message: "Admin created successfully", token });
  } catch (err) {
    console.error("Verify OTP Error:", err);
    res.status(500).json({ success: false, message: "Failed to create admin" });
  }
});

// --- Normal Register (user signup) ---
app.post("/auth/register", async (req, res) => {
  try {
    const { name, email, password, role } = req.body;

    let user = await User.findOne({ username: email });
    if (user) return res.status(400).json({ message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    user = new User({
      username: email,
      password: hashedPassword,
      role: role || "user",
      name,
    });
    await user.save();

    const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, "secretkey");
    res.json({ token, role: user.role, name: user.name, id: user._id });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// --- Login (case-insensitive) ---
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ username: { $regex: `^${email}$`, $options: "i" } });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id, role: user.role, name: user.name }, "secretkey");
    res.json({ token, role: user.role, name: user.name, id: user._id });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// --- Articles ---
app.post("/articles/add", upload.single("image"), async (req, res) => {
  try {
    const { title, description, author } = req.body;
    const imageUrl = req.file ? req.file.path : "";

    const newArticle = new Article({ title, description, image: imageUrl, author });
    await newArticle.save();
    res.json({ message: "Article added!", article: newArticle });
  } catch (err) {
    res.status(500).json({ error: "Error adding article" });
  }
});

app.post("/articles/upload-image", upload.single("image"), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "No file uploaded" });
    res.json({ url: req.file.path });
  } catch (err) {
    res.status(500).json({ error: "Image upload failed" });
  }
});

app.get("/articles", async (req, res) => {
  const articles = await Article.find().populate("comments.user", "username");
  res.json(articles);
});

app.get("/articles/:id", async (req, res) => {
  const article = await Article.findById(req.params.id).populate("comments.user", "username");
  res.json(article);
});

// Toggle like/unlike
app.post("/articles/:id/like", async (req, res) => {
  const { userId } = req.body;
  const article = await Article.findById(req.params.id);

  if (!article) return res.status(404).json({ message: "Article not found" });

  const index = article.likes.findIndex(id => id.toString() === userId);

  if (index === -1) {
    article.likes.push(userId);
  } else {
    article.likes.splice(index, 1);
  }

  await article.save();
  const populated = await Article.findById(req.params.id).populate("likes", "name username");
  res.json({ likes: populated.likes });
});

app.post("/articles/:id/unlike", async (req, res) => {
  const { userId } = req.body;
  const article = await Article.findById(req.params.id);
  article.likes = article.likes.filter(id => id.toString() !== userId);
  await article.save();
  res.json({ likes: article.likes });
});

app.post("/articles/:id/comment", async (req, res) => {
  const { userId, text } = req.body;
  const article = await Article.findById(req.params.id);
  article.comments.push({ user: userId, text });
  await article.save();
  const populated = await article.populate("comments.user", "username");
  res.json(populated.comments);
});

app.get("/articles/search/:query", async (req, res) => {
  const { query } = req.params;
  const articles = await Article.find({ title: { $regex: query, $options: "i" } }).select("title _id");
  res.json(articles);
});

app.delete("/articles/:id", verifyToken, async (req, res) => {
  try {
    const article = await Article.findById(req.params.id);
    if (!article) return res.status(404).send("Article not found");

    if (req.user.role !== "admin" && article.author !== req.user.name)
      return res.status(403).send("Unauthorized");

    await Article.findByIdAndDelete(req.params.id);
    res.send({ message: "Article deleted" });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

// --- Start server ---
app.listen(5000, () => console.log("Server running on port 5000"));
