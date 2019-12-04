const app = require("./app");
const https = require("https");
const fs = require("fs");
const PORT = 3020;
const rootCas = require("ssl-root-cas/latest").create();
rootCas
  .addFile("./certificates/local.photo-ac.com-key.pem")
  .addFile("./certificates/local.photo-ac.com.pem");
// app.listen(PORT, () => {
//   console.info(`photo-sso-consumer listening on port ${PORT}`);
// });

const options = {
  key: fs.readFileSync("./certificates/local.photo-ac.com-key.pem"),
  cert: fs.readFileSync("./certificates/local.photo-ac.com.pem")
};
https.globalAgent.options.ca = rootCas;
https.createServer(options, app).listen(PORT, () => {
  console.info(`photo-sso-consumer listening on port ${PORT}`);
});
