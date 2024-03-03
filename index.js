import express from "express";
import bodyParser from "body-parser";
import { MongoClient } from "mongodb";
import cors from "cors";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(bodyParser.json());
app.use(cors());

const PORT = process.env.PORT || 4000;

const MONGO_URI = process.env.MONGO_URL || "";

let db;

MongoClient.connect(MONGO_URI)
  .then((client) => {
    db = client.db("StellarPay");
    console.log("MongoDB connected successfully");
  })
  .catch((error) => {
    console.error("Error connecting to MongoDB:", error);
  });

app.get("/", (req, res) => {
  res.send("Hello, world!");
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Find user by username
    const user = await db.collection("users").findOne({ username });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.hashedPassword);
    if (!isPasswordValid) {
      return res.status(401).json({ message: "Invalid password" });
    }

    // Decrypt the private key using the user's password
    const decipher = crypto.createDecipher("aes-256-cbc", password);
    let decryptedPrivateAddress = decipher.update(
      user.encryptedPrivateAddress,
      "hex",
      "utf8"
    );
    decryptedPrivateAddress += decipher.final("utf8");

    // Return public address and decrypted private address upon successful login
    res.json({
      message: "Login successful",
      publicAddress: user.publicAddress,
      privateAddress: decryptedPrivateAddress,
    });
  } catch (error) {
    console.error("Error logging in:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

// POST endpoint for user registration
app.post("/register", async (req, res) => {
  const { username, password, publicAddress, privateAddress } = req.body;

  try {
    // Check if user already exists
    const existingUser = await db.collection("users").findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    // Encrypt the private key using the user's password
    const cipher = crypto.createCipher("aes-256-cbc", password);
    let encryptedPrivateAddress = cipher.update(privateAddress, "utf8", "hex");
    encryptedPrivateAddress += cipher.final("hex");

    // Insert user data into the database
    await db.collection("users").insertOne({
      username,
      hashedPassword: await bcrypt.hash(password, 10),
      publicAddress,
      encryptedPrivateAddress,
    });

    res.json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Error registering user:", error);
    res.status(500).json({ message: "Internal server error" });
  }
});

app.listen(PORT, () =>
  console.log(`Server is running on http://localhost:${PORT}`)
);
