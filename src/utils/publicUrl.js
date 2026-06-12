/**
 * Build the public base URL (scheme + host + API Gateway stage) for absolute
 * links the frontend will fetch — e.g. "https://api.respyr.ai/v1".
 *
 * Resolution order:
 *   1. PUBLIC_API_BASE_URL env override (use in local dev, e.g.
 *      "http://localhost:3000"). Trailing slashes are stripped.
 *   2. Derived from the incoming request: scheme + host + stage. The stage
 *      (e.g. "v1") is attached in lambda.js from event.requestContext.stage,
 *      so it tracks the Lambda stage dynamically and never needs hardcoding.
 *
 * Returns "" when neither an override nor a request host is available; callers
 * then fall back to relative URLs.
 */
const buildPublicBaseUrl = (req) => {
  const override = (process.env.PUBLIC_API_BASE_URL || "").replace(/\/+$/, "");
  if (override) return override;

  if (!req) return "";

  const proto = String(
    req.headers?.["x-forwarded-proto"] || req.protocol || "https"
  )
    .split(",")[0]
    .trim();

  const host = req.headers?.["x-forwarded-host"] || req.headers?.host;
  if (!host) return "";

  const stage = req.apiGatewayStage;
  const stageSegment =
    stage && stage !== "$default" ? `/${encodeURIComponent(stage)}` : "";

  return `${proto}://${host}${stageSegment}`;
};

module.exports = { buildPublicBaseUrl };
