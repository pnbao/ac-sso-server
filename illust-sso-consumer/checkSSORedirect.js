const url = require("url");
const axios = require("axios");
const { URL } = url;
const { verifyJwtToken } = require("./jwt_verify");
// const ssoServerJWTURL = "http://account.acworks.co.jp:3010";
const ssoServerJWTURL = "https://localhost:3010";
const ssoRedirect = () => {
  return async function(req, res, next) {
    // check if the req has the queryParameter as ssoToken
    // and who is the referer.
    const { ssoToken } = req.query;
    if (ssoToken != null) {
      // to remove the ssoToken in query parameter redirect.
      const redirectURL = url.parse(req.url).pathname;
      try {
        const response = await axios.get(
          `${ssoServerJWTURL}/acsso/verifytoken?ssoToken=${ssoToken}`,
          {
            headers: {
              Authorization: "Bearer 1g0jJwGmRQhJwvwNOrY4i90kD0m"
            }
          }
        );
        const { token } = response.data;
        const decoded = await verifyJwtToken(token);
        console.log("inside illust ssoRedirect, have user, have url");

        // now that we have the decoded jwt, use the,
        // global-session-id as the session id so that
        // the logout can be implemented with the global session.
        req.session.user = decoded;
      } catch (err) {
        return next(err);
      }

      return res.redirect(`${redirectURL}`);
    }

    return next();
  };
};

module.exports = ssoRedirect;
