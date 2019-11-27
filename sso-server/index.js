const app = require("./app");
const PORT = 3010;
// const serverless = require('serverless-http');

app.listen(PORT, () => {
  console.info(`sso-server listening on port ${PORT}`);
});
// module.exports.handler = serverless(app);


