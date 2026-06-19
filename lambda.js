const serverless = require("serverless-http");
const app = require("./src/index");

module.exports.handler = serverless(app, {
  basePath: false,

  // Binary responses (profile images from get_profile_image) must be
  // base64-encoded with isBase64Encoded:true so API Gateway returns the raw
  // bytes instead of UTF-8-mangling them into a corrupt/broken image. JSON
  // responses are unaffected — they stay text. Requires the API Gateway
  // binaryMediaTypes to include "*/*" (see deploy notes).
  binary: ["image/png", "image/jpeg", "image/webp"],

  request: function (request, event, context) {
    /**
     * Safe Lambda logging only.
     * Do not log:
     * - Authorization header
     * - request body
     * - cookies
     * - health/test/client data
     */
    // Support both API Gateway payload formats:
    //  - REST API / HTTP API v1.0 -> event.path, event.httpMethod
    //  - HTTP API v2.0            -> event.rawPath, event.requestContext.http.method
    console.log("Lambda request:", {
      path: event.path || event.rawPath || event.requestContext?.http?.path,
      httpMethod:
        event.httpMethod || event.requestContext?.http?.method,
      requestId: context.awsRequestId,
    });

    // Expose the API Gateway stage (e.g. "v1") to the Express app so it can
    // build absolute public URLs that include the stage segment dynamically.
    request.apiGatewayStage = event.requestContext?.stage;

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
