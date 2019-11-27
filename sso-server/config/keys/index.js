const fs = require("fs");
const path = require("path");

const privateKeyFilePath =
  process.env.JWT_SSO_PRIVATE_KEY_FILE ||
  path.resolve(__dirname, "./jwtPrivate.key");

const privateCert = fs.readFileSync(privateKeyFilePath);

const jwtValidatityKey = "ac-sso-jwt-validatity";

module.exports = Object.assign(
  {},
  {
    privateCert,

    jwtValidatityKey
  }
);
