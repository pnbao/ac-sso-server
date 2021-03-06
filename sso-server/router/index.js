const express = require("express");
const router = express.Router();
const controller = require("../controller");

router
  .route("/login")
  .get(controller.login)
  .post(controller.doLogin);
router.post("/googlesignin", controller.googleSignIn);
router.post("/facebooksignin", controller.facebookSignIn);
router.get("/twitterConnect", controller.twitterConnect);
router.get("/twitterSignIn", controller.twitterSignIn);
router.get("/twitterCallback", controller.twitterCallback);
router.get("/verifytoken", controller.verifySsoToken);
router.get("/logout", controller.logout);
router.get("/logoutAllSites", controller.logoutAllSites);
router.get("/isLoggedOut", controller.isLoggedOut);

module.exports = router;
