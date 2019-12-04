const app = require("./app");
const https = require("https");
const fs = require("fs");
const PORT = 3030;
const rootCas = require("ssl-root-cas/latest").create();
rootCas
  .addFile("./certificates/local.illust-ac.com-key.pem")
  .addFile("./certificates/local.illust-ac.com.pem");

// app.listen(PORT, () => {
//   console.info(`illust-sso-consumer listening on port ${PORT}`);
// });

const options = {
  key: fs.readFileSync("./certificates/local.illust-ac.com-key.pem"),
  cert: fs.readFileSync("./certificates/local.illust-ac.com.pem")
};
https.globalAgent.options.ca = rootCas;
https.createServer(options, app).listen(PORT, () => {
  console.info(`illust-sso-consumer listening on port ${PORT}`);
});
