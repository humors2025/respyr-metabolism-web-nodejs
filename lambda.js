const serverless = require("serverless-http");
const app = require("./src/index");

module.exports.handler = serverless(app, {
  basePath: false,

  // ---------------------------------------------------------------------------
  // Binary response handling.
  //
  // serverless-http defaults to encoding every response body as UTF-8. That is
  // correct for JSON, but it CORRUPTS raw image buffers: get_profile_image does
  // res.end(<png/jpeg/webp buffer>), and without this option serverless-http
  // runs buffer.toString('utf8') on it, mangling every non-ASCII byte and
  // returning isBase64Encoded:false. The browser then receives broken bytes
  // labelled image/png and shows a broken-image icon.
  //
  // Listing the image content types here makes serverless-http base64-encode
  // those responses and set isBase64Encoded:true. On HTTP API (v2) API Gateway
  // automatically decodes that back to binary. JSON responses (application/json)
  // do not match these patterns and are still sent as UTF-8 text.
  //
  // NOTE (REST API / v1 only): if this Lambda is ever fronted by a REST API
  // instead of an HTTP API, you must ALSO add Binary Media Types in API Gateway
  // (e.g. image/png, image/jpeg, image/webp, or */*) — HTTP APIs need no such
  // setting.
  // ---------------------------------------------------------------------------
  binary: ["image/*", "application/pdf", "application/octet-stream"],

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

// module.exports.handler = serverless(app, {
//   basePath: false,

//   request: function (request, event, context) {
//     /**
//      * Safe Lambda logging only.
//      * Do not log:
//      * - Authorization header
//      * - request body
//      * - cookies
//      * - health/test/client data
//      */
//     // Support both API Gateway payload formats:
//     //  - REST API / HTTP API v1.0 -> event.path, event.httpMethod
//     //  - HTTP API v2.0            -> event.rawPath, event.requestContext.http.method
//     console.log("Lambda request:", {
//       path: event.path || event.rawPath || event.requestContext?.http?.path,
//       httpMethod:
//         event.httpMethod || event.requestContext?.http?.method,
//       requestId: context.awsRequestId,
//     });

//     // Expose the API Gateway stage (e.g. "v1") to the Express app so it can
//     // build absolute public URLs that include the stage segment dynamically.
//     request.apiGatewayStage = event.requestContext?.stage;

//     return request;
//   },
// });









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
