const express = require("express");
const router = express.Router();
const controller = require("../controller");

router
  .route("/login")
  .get(controller.login)
  .post(controller.doLogin);

router.get("/verifytoken", controller.verifySsoToken);

//logout route
router.get('/logout', controller.logout);
router.get('/logoutAllSites', controller.logoutAllSites);
router.get('/isLoggedOut', controller.isLoggedOut);

module.exports = router;
