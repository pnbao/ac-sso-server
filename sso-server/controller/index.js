const uuidv4 = require("uuid/v4");
const Hashids = require("hashids");
const URL = require("url").URL;
const hashids = new Hashids();
const { genJwtToken } = require("./jwt_helper");
const couchbase = require("couchbase");
const path = require("path");
require("dotenv").config();
const re = /(\S+)\s+(\S+)/;
const { OAuth2Client } = require("google-auth-library");
const client = new OAuth2Client(process.env.AUTHENTICATION_GOOGLE_CLIENT);
const CryptoJS = require("crypto-js");
const oauth = require("oauth");
const _twitterConsumerKey = process.env.TWITTER_CONSUMER_KEY;
const _twitterConsumerSecret = process.env.TWITTER_CONSUMER_SECRET;
const twitterCallbackUrl = process.env.TWITTER_CALLBACK_URL;
const inspect = require("util-inspect");
const consumer = new oauth.OAuth(
  "https://twitter.com/oauth/request_token",
  "https://twitter.com/oauth/access_token",
  _twitterConsumerKey,
  _twitterConsumerSecret,
  "1.0A",
  twitterCallbackUrl,
  "HMAC-SHA1"
);

// Note: express http converts all headers
// to lower case.
const AUTH_HEADER = "authorization";
const BEARER_AUTH_SCHEME = "bearer";

const cluster = new couchbase.Cluster(process.env.COUCHBASE_CLUSTER);

cluster.authenticate(
  process.env.COUCHBASE_CLUSTER_USERNAME,
  process.env.COUCHBASE_CLUSTER_PASSWORD
);

function getAppName(serviceURL) {
  let params = path
    .basename(serviceURL)
    .split(".")
    .join(":")
    .split(":");
  if (params.includes("photo-ac")) return "Photo AC";
  else if (params.includes("illust-ac")) return "Illust AC";
}

function parseAuthHeader(hdrValue) {
  if (typeof hdrValue !== "string") {
    return null;
  }
  const matches = hdrValue.match(re);
  return matches && { scheme: matches[1], value: matches[2] };
}

const fromAuthHeaderWithScheme = function(authScheme) {
  const authSchemeLower = authScheme.toLowerCase();
  return function(request) {
    let token = null;
    if (request.headers[AUTH_HEADER]) {
      const authParams = parseAuthHeader(request.headers[AUTH_HEADER]);
      if (authParams && authSchemeLower === authParams.scheme.toLowerCase()) {
        token = authParams.value;
      }
    }
    return token;
  };
};

const fromAuthHeaderAsBearerToken = function() {
  return fromAuthHeaderWithScheme(BEARER_AUTH_SCHEME);
};

const appTokenFromRequest = fromAuthHeaderAsBearerToken();

// app token to validate the request is coming from the authenticated server only.
const appTokenDB = {
  photo_sso_consumer: process.env.PHOTO_AC_APP_TOKEN,
  illust_sso_consumer: process.env.ILLUST_AC_APP_TOKEN
};

const alloweOrigin = {
  "https://local.photo-ac.com:3020": true,
  "https://local.illust-ac.com:3030": true
};

const deHyphenatedUUID = () => uuidv4().replace(/-/gi, "");
const encodedId = () => hashids.encodeHex(deHyphenatedUUID());

// A temporary cache to store all the application that has login using the current session.
// It can be useful for variuos audit purpose
const sessionUser = {};
const sessionApp = {};

const originAppName = {
  "https://local.photo-ac.com:3020": "photo_sso_consumer",
  "https://local.illust-ac.com:3030": "illust_sso_consumer"
};

// these token are for the validation purpose
const intrmTokenCache = {};

const fillIntrmTokenCache = (origin, id, intrmToken) => {
  intrmTokenCache[intrmToken] = [id, originAppName[origin]];
};
const storeApplicationInCache = (origin, id, intrmToken) => {
  if (sessionApp[id] == null) {
    sessionApp[id] = {
      [originAppName[origin]]: true
    };
    fillIntrmTokenCache(origin, id, intrmToken);
  } else {
    sessionApp[id][originAppName[origin]] = true;
    fillIntrmTokenCache(origin, id, intrmToken);
  }
  console.log(
    "session app:",
    { ...sessionApp },
    "session user:",
    { ...sessionUser },
    "intermediate token:",
    { ...intrmTokenCache }
  );
};

const generatePayload = ssoToken => {
  const globalSessionToken = intrmTokenCache[ssoToken][0];
  const appName = intrmTokenCache[ssoToken][1];
  const userEmail = sessionUser[globalSessionToken].email;
  const appPolicy = sessionUser[globalSessionToken].appPolicy[appName];
  const premium = appPolicy.premium;
  const payload = {
    ...{ ...appPolicy },
    ...{
      userEmail,
      premium: premium,
      uid: sessionUser[globalSessionToken].userId,
      // global SessionID for the logout functionality.
      globalSessionID: globalSessionToken
    }
  };
  return payload;
};

const verifySsoToken = async (req, res, next) => {
  const appToken = appTokenFromRequest(req);
  const { ssoToken } = req.query;
  // if the application token is not present or ssoToken request is invalid
  // if the ssoToken is not present in the cache some is
  // smart.
  if (
    appToken == null ||
    ssoToken == null ||
    intrmTokenCache[ssoToken] == null
  ) {
    return res.status(400).json({ message: "badRequest" });
  }

  // if the appToken is present and check if it's valid for the application
  const appName = intrmTokenCache[ssoToken][1];
  const globalSessionToken = intrmTokenCache[ssoToken][0];
  // If the appToken is not equal to token given during the sso app registraion or later stage than invalid
  if (
    appToken !== appTokenDB[appName] ||
    sessionApp[globalSessionToken][appName] !== true
  ) {
    return res.status(403).json({ message: "Unauthorized" });
  }
  // checking if the token passed has been generated
  const payload = generatePayload(ssoToken);

  const token = await genJwtToken(payload);
  // delete the itremCache key for no futher use,
  delete intrmTokenCache[ssoToken];
  return res.status(200).json({ token });
};

const doLogin = (req, res, next) => {
  const { email, password } = req.body;
  const bucket = cluster.openBucket("users", function(err) {
    if (err) {
      res.status(503).json({ message: "Login Server Internal Error" });
    }

    bucket.get(email, function(err, result) {
      if (err) {
        return res.status(404).json({ message: "Error Invalid email" });
      }
      var doc = result.value;
      if (doc === undefined) {
        return res.status(404).json({ message: "Invalid email" });
      } else {
        if (!(password === doc.password)) {
          return res
            .status(404)
            .json({ message: "Invalid email and password" });
        }
        const { serviceURL } = req.query;
        const id = encodedId();
        req.session.user = id;
        sessionUser[id] = {
          email: email,
          appPolicy: doc.appPolicy,
          userId: doc.userId
        };
        if (serviceURL == null) {
          return res.redirect("/");
        }
        const url = new URL(serviceURL);
        const intrmid = encodedId();
        storeApplicationInCache(url.origin, id, intrmid);
        console.log("inside doLogin, have user, have url");

        return res.redirect(`${serviceURL}?ssoToken=${intrmid}`);
      }
    });
  });
};
const twitterConnect = async (req, res, next) => {
  const { serviceURL } = req.query;
  consumer.getOAuthRequestToken(function(
    error,
    oauthToken,
    oauthTokenSecret,
    results
  ) {
    if (error) {
      console.log("error inside twitterConnect: " + JSON.stringify(error));
      res
        .status(500)
        .send("Error getting OAuth request token : " + inspect(error));
    } else {
      req.session.oauthRequestToken = oauthToken;
      req.session.oauthRequestTokenSecret = oauthTokenSecret;
      req.session.serviceURL = serviceURL;
      console.log("Double check on 2nd step");
      console.log("------------------------");
      console.log("<<" + req.session.oauthRequestToken);
      console.log("<<" + req.session.oauthRequestTokenSecret);
      console.log("<<" + req.session.serviceURL);
      return res
        .status(200)
        .send(
          "https://api.twitter.com/oauth/authenticate?oauth_token=" +
            req.session.oauthRequestToken
        );
    }
  });
};
const twitterSignIn = async (req, res, next) => {
  const { serviceURL } = req.query;
  consumer.get(
    "https://api.twitter.com/1.1/account/verify_credentials.json?include_email=true",
    req.session.oauthAccessToken,
    req.session.oauthAccessTokenSecret,
    function(error, data, response) {
      if (error) {
        console.log(error);
        res.redirect("/acsso/twitterConnect?serviceURL=" + serviceURL);
      } else {
        const parsedData = JSON.parse(data);
        const email = parsedData.email;
        try {
          const bucket = cluster.openBucket("users", function(err) {
            if (err) {
              res.status(503).json({ message: "Login Server Internal Error" });
            }

            bucket.get(email, function(err, result) {
              if (err) {
                return res.status(404).json({ message: "Error Invalid email" });
              }
              var doc = result.value;
              if (doc === undefined) {
                return res.status(404).json({ message: "Invalid email" });
              } else {
                const serviceURL = req.session.serviceURL;
                const id = encodedId();
                req.session.user = id;
                sessionUser[id] = {
                  email: email,
                  appPolicy: doc.appPolicy,
                  userId: doc.userId,
                  origin: "twitter"
                };
                if (serviceURL == null) {
                  return res.redirect("/");
                }
                const url = new URL(serviceURL);
                const intrmid = encodedId();
                storeApplicationInCache(url.origin, id, intrmid);
                console.log("inside twitter, have user, have url");
                return res.redirect(`${serviceURL}?ssoToken=${intrmid}`);
              }
            });
          });
        } catch (error) {
          return res.json({ message: error });
        }
      }
    }
  );
};
const twitterCallback = async (req, res, next) => {
  console.log("------------------------");
  console.log(">>" + req.session.oauthRequestToken);
  console.log(">>" + req.session.oauthRequestTokenSecret);
  console.log(">>" + req.query.oauth_verifier);
  consumer.getOAuthAccessToken(
    req.session.oauthRequestToken,
    req.session.oauthRequestTokenSecret,
    req.query.oauth_verifier,
    function(error, oauthAccessToken, oauthAccessTokenSecret, results) {
      if (error) {
        res
          .status(500)
          .send(
            "Error getting OAuth access token : " +
              inspect(error) +
              "[" +
              oauthAccessToken +
              "]" +
              "[" +
              oauthAccessTokenSecret +
              "]" +
              "[" +
              inspect(result) +
              "]"
          );
      } else {
        req.session.oauthAccessToken = oauthAccessToken;
        req.session.oauthAccessTokenSecret = oauthAccessTokenSecret;
        res.redirect("/acsso/twitterSignIn");
      }
    }
  );
};

const googleSignIn = async (req, res, next) => {
  const { email, token } = req.body;
  try {
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.AUTHENTICATION_GOOGLE_CLIENT
    });
    const payload = ticket.getPayload();
    const bucket = cluster.openBucket("users", function(err) {
      if (err) {
        res.status(503).json({ message: "Login Server Internal Error" });
      }

      bucket.get(payload.email, function(err, result) {
        if (err) {
          return res.status(404).json({ message: "Error Invalid email" });
        }
        var doc = result.value;
        if (doc === undefined) {
          return res.status(404).json({ message: "Invalid email" });
        } else {
          const { serviceURL } = req.query;
          const id = encodedId();
          req.session.user = id;
          sessionUser[id] = {
            email: email,
            appPolicy: doc.appPolicy,
            userId: doc.userId,
            origin: "google"
          };
          if (serviceURL == null) {
            return res.redirect("/");
          }
          const url = new URL(serviceURL);
          const intrmid = encodedId();
          storeApplicationInCache(url.origin, id, intrmid);
          console.log("inside google, have user, have url");
          return res.redirect(`${serviceURL}?ssoToken=${intrmid}`);
        }
      });
    });
  } catch (error) {
    return res.json({ message: error });
  }
};

const facebookSignIn = async (req, res, next) => {
  const { email } = req.body;
  try {
    const bucket = cluster.openBucket("users", function(err) {
      if (err) {
        res.status(503).json({ message: "Login Server Internal Error" });
      }

      bucket.get(email, function(err, result) {
        if (err) {
          return res.status(404).json({ message: "Error Invalid email" });
        }
        var doc = result.value;
        if (doc === undefined) {
          return res.status(404).json({ message: "Invalid email" });
        } else {
          const { serviceURL } = req.query;
          const id = encodedId();
          req.session.user = id;
          sessionUser[id] = {
            email: email,
            appPolicy: doc.appPolicy,
            userId: doc.userId,
            origin: "facebook"
          };
          if (serviceURL == null) {
            return res.redirect("/");
          }
          const url = new URL(serviceURL);
          const intrmid = encodedId();
          storeApplicationInCache(url.origin, id, intrmid);
          console.log("inside facebook, have user, have url");
          return res.redirect(`${serviceURL}?ssoToken=${intrmid}`);
        }
      });
    });
  } catch (error) {
    return res.json({ message: error });
  }
};

const login = (req, res, next) => {
  // The req.query will have the redirect url where we need to redirect after successful
  // login and with sso token.
  // This can also be used to verify the origin from where the request has came in
  // for the redirection
  const { serviceURL } = req.query;
  // direct access will give the error inside new URL.
  if (serviceURL != null) {
    const url = new URL(serviceURL);
    if (alloweOrigin[url.origin] !== true) {
      return res
        .status(400)
        .json({ message: "Your are not allowed to access the sso-server" });
    }
  }

  if (req.session.user != null && serviceURL == null) {
    return res.redirect("/");
  }
  // if global session already has the user directly redirect with the token
  if (req.session.user != null && serviceURL != null) {
    const url = new URL(serviceURL);
    const intrmid = encodedId();
    storeApplicationInCache(url.origin, req.session.user, intrmid);
    console.log("inside login, have user, have url");
    return res.redirect(`${serviceURL}?ssoToken=${intrmid}`);
  }

  return res.render("login", {
    title: "ACworks Account | Login",
    origin: getAppName(serviceURL),
    YOUR_CLIENT_ID: process.env.AUTHENTICATION_GOOGLE_CLIENT
  });
};

const isLoggedOut = (req, res, next) => {
  const { globalSessionToken, serviceURL } = req.query;
  // direct access will give the error inside new URL.
  if (serviceURL != null) {
    const url = new URL(serviceURL);
    if (alloweOrigin[url.origin] !== true) {
      return res
        .status(400)
        .json({ message: "Your are not allowed to access the sso-server" });
    }
  }
  return res.json(sessionUser[globalSessionToken] == null);
};

const logout = (req, res, next) => {
  const { globalSessionToken, serviceURL } = req.query;
  res.clearCookie(globalSessionToken);
  req.session.destroy();
  return res.redirect(serviceURL + "#logout");
};

const logoutAllSites = (req, res, next) => {
  const { globalSessionToken, serviceURL } = req.query;
  delete sessionApp[globalSessionToken];
  delete sessionUser[globalSessionToken];

  console.log(
    "session app:",
    { ...sessionApp },
    "session user:",
    { ...sessionUser },
    "intermediate token:",
    { ...intrmTokenCache }
  );
  res.clearCookie(globalSessionToken);
  req.session.destroy();
  return res.redirect(serviceURL + "#logout");
};

module.exports = Object.assign(
  {},
  {
    doLogin,
    login,
    googleSignIn,
    facebookSignIn,
    twitterCallback,
    twitterConnect,
    twitterSignIn,
    logout,
    logoutAllSites,
    isLoggedOut,
    verifySsoToken
  }
);
