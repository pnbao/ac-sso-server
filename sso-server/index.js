const app = require("./app");
const https = require("https");
const fs = require("fs");
const rootCas = require("ssl-root-cas/latest").create();

rootCas
  .addFile("./certificates/localhost-key.pem")
  .addFile("./certificates/localhost.pem");

const PORT = 3010;
const options = {
  key: fs.readFileSync("./certificates/localhost-key.pem"),
  cert: fs.readFileSync("./certificates/localhost.pem")
};

// app.listen(PORT, () => {
//   console.info(`sso-server listening on port ${PORT}`);
// });
https.globalAgent.options.ca = rootCas;
https.createServer(options, app).listen(PORT, () => {
  console.info(`sso-server listening on port ${PORT}`);
});
