const jwt = require("jsonwebtoken");
const config = require("config");

const tokenFunc = (req, res, next) => {
  // Get Token from header
  const token = req.header("x-auth-token");
  if (!token) {
    return res.status(401).json({ ms: "no token, authorization denied" });
  }

  // verify token
  try {
    const decoded = jwt.verify(token, config.get("jwtSecret"));
    req.user = decoded.user;
    next();
  } catch (err) {
    res.status(401).json({ msg: "Token is not valid" });
  }
};

module.exports = tokenFunc;
