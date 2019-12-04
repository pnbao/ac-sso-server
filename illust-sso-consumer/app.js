const express = require("express");
const morgan = require("morgan");
const app = express();
const engine = require("ejs-mate");
const session = require("express-session");
const cors = require("cors");
const isAuthenticated = require("./isAuthenticated");
const checkSSORedirect = require("./checkSSORedirect");
// const origin = "http://account.acworks.co.jp:3010";
const origin = "https://localhost:3010";

app.use(
  session({
    secret: "keyboard cat",
    resave: false,
    saveUninitialized: true
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(cors({ origin: origin, credentials: true }));

app.use(morgan("dev"));
app.engine("ejs", engine);
app.set("views", __dirname + "/views");
app.set("view engine", "ejs");
app.use(checkSSORedirect());

app.get("/", isAuthenticated, (req, res, next) => {
  res.render("index", {
    what: `Illust SSO-Consumer ${JSON.stringify(
      req.session.user ? req.session.user : "Not Logged In"
    )}`,
    title: "Illust SSO-Consumer | Illust Home"
  });
});

app.get("/logout", (req, res, next) => {
  console.log("user", req.session.user);
  const globalSessionToken = req.session.user.globalSessionID;
  const redirectURL = `${req.protocol}://${req.headers.host}`;
  res.clearCookie(globalSessionToken);
  req.session.destroy();
  res.redirect(
    origin +
      "/acsso/logout?globalSessionToken=" +
      globalSessionToken +
      "&serviceURL=" +
      redirectURL
  );
});

app.get("/logoutAllSites", (req, res, next) => {
  console.log("user", req.session.user);
  const globalSessionToken = req.session.user.globalSessionID;
  const redirectURL = `${req.protocol}://${req.headers.host}`;
  res.clearCookie(globalSessionToken);
  req.session.destroy();
  res.redirect(
    origin +
      "/acsso/logoutAllSites?globalSessionToken=" +
      globalSessionToken +
      "&serviceURL=" +
      redirectURL
  );
});

app.use((req, res, next) => {
  // catch 404 and forward to error handler
  const err = new Error("Resource Not Found");
  err.status = 404;
  next(err);
});

app.use((err, req, res, next) => {
  console.error({
    message: err.message,
    error: err
  });
  const statusCode = err.status || 500;
  let message = err.message || "Internal Server Error";

  if (statusCode === 500) {
    message = "Internal Server Error";
  }
  res.status(statusCode).json({ message });
});

module.exports = app;
