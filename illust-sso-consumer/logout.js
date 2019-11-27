const logout = (req, res, next) => {
  // simple check to see if the user is authenicated or not,
  // if not redirect the user to the SSO Server for Login
  // pass the redirect URL as current URL
  // serviceURL is where the sso should redirect in case of valid user
  console.log("user", req.session.user);
  const globalSessionToken = req.session.user.globalSessionID;
  const redirectURL = `${req.protocol}://${req.headers.host}`;
  req.session.destroy();
  res.redirect(
    "http://account.acworks.co.jp:3010/acsso/logout?globalSessionToken=" +
      globalSessionToken +
      "&serviceURL=" +
      redirectURL
  );
  next();
};

module.exports = logout;
