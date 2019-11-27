const fetch = require("node-fetch");
const isAuthenticated = async (req, res, next) => {
  // simple check to see if the user is authenicated or not,
  // if not redirect the user to the SSO Server for Login
  // pass the redirect URL as current URL
  // serviceURL is where the sso should redirect in case of valid user
  const redirectURL = `${req.protocol}://${req.headers.host}${req.path}`;
  if (req.session.user == null) {
    return res.redirect(
      `http://account.acworks.co.jp:3010/acsso/login?serviceURL=${redirectURL}`
    );
  }
  if (req.session.user != null) {
    await fetch(
      `http://account.acworks.co.jp:3010/acsso/isLoggedOut?serviceURL=${redirectURL}`
    )
      .then(res => res.json())
      .then(json => console.log(json));
  }
  next();
};

module.exports = isAuthenticated;
