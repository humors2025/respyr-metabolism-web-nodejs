const serverless = require("serverless-http");
const app = require("./src/index");

module.exports.handler = serverless(app, {
  basePath: false,

  request: function (request, event, context) {
    /**
     * Safe Lambda logging only.
     * Do not log:
     * - Authorization header
     * - request body
     * - cookies
     * - health/test/client data
     */
    console.log("Lambda request:", {
      path: event.path,
      httpMethod: event.httpMethod,
      requestId: context.awsRequestId,
    });

    return request;
  },
});









// const serverless = require("serverless-http");
// const app = require("./src/index");

// // Create the serverless handler with basePath disabled
// module.exports.handler = serverless(app, {
//   basePath: false,
//   request: function(request, event, context) {
//     // Log the incoming event for debugging
//     console.log("Lambda Event Received:");
//     console.log("Path:", event.path);
//     console.log("HTTP Method:", event.httpMethod);
    
//     // You can also modify request here if needed
//     return request;
//   }
// });






// const serverless = require('serverless-http');
// const app = require('./src/index');

// module.exports.handler = serverless(app);
