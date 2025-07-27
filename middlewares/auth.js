import jwt from "jsonwebtoken";

// Middleware function to decode jwt token to get clerkId
const authUser = async (req, res, next) => {
  try {
    const { token } = req.headers;

    // Token required
    if (!token) {
      return res.status(401).json({ success: false, message: "Not Authorized. Login again!" });
    }

    // Decode token (no secret because it's a session token from Clerk)
    const token_decode = jwt.decode(token);

    // Check if token_decode is valid and has clerkId
    if (!token_decode || !token_decode.clerkId) {
      return res.status(403).json({ success: false, message: "Invalid token. ClerkId not found" });
    }

    // Attach clerkId to request
    req.body.clerkId = token_decode.clerkId;

    // Continue
    next();

  } catch (error) {
    console.log(error);
    res.status(500).json({ success: false, message: error.message });
  }
};

export default authUser;
