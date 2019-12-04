const fetch = require("node-fetch");
const isAuthenticated = async (req, res, next) => {
  // simple check to see if the user is authenicated or not,
  // if not redirect the user to the SSO Server for Login
  // pass the redirect URL as current URL
  // serviceURL is where the sso should redirect in case of valid user
  console.log("inside photo auth");

  const redirectURL = `${req.protocol}://${req.headers.host}${req.path}`;
  // const origin = "http://account.acworks.co.jp:3010";
  const origin = "https://localhost:3010";
  if (req.session.user == null) {
    console.log("inside photo auth, not user");
    return res.redirect(`${origin}/acsso/login?serviceURL=${redirectURL}`);
  }
  if (req.session.user != null) {
    console.log("inside photo auth, have user");

    const globalSessionToken = req.session.user.globalSessionID;
    await fetch(
      `${origin}/acsso/isLoggedOut?globalSessionToken=${globalSessionToken}&serviceURL=${redirectURL}`
    )
      .then(res => res.json())
      .then(isLoggedout => {
        if (isLoggedout) {
          req.session.destroy();
          res.redirect("/");
        }
      });
  }
  next();
};

module.exports = isAuthenticated;
