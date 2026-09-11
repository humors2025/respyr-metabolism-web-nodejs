"use strict";

const { S3Client } = require("@aws-sdk/client-s3");

const AGREEMENT_S3_REGION =
  process.env.AGREEMENT_S3_REGION || process.env.AWS_REGION || "us-west-2";

const AGREEMENT_S3_BUCKET = process.env.AGREEMENT_S3_BUCKET || "";

// ---------------------------------------------------------------------------
// UAT ONLY: skip storing agreement PDFs.
//
// When active, agreement-upload-url returns no upload link, accept-invite does
// NOT verify that a PDF exists in S3, and the agreement row is recorded with
// the marker bucket below instead of a real bucket, so list-accepted-agreements
// returns no download link for it.
//
// It requires BOTH variables so a single stray setting can never disable
// agreement collection in production:
//   APP_ENV=uat
//   SKIP_AGREEMENT_STORAGE=true
// Production sets neither, so this is always false there and the code path is
// byte-for-byte the previous behaviour. NOTE: with this on, UAT does not test
// the real agreement upload/verification path.
// ---------------------------------------------------------------------------
const AGREEMENT_STORAGE_SKIPPED =
  String(process.env.APP_ENV || "").trim().toLowerCase() === "uat" &&
  String(process.env.SKIP_AGREEMENT_STORAGE || "").trim().toLowerCase() ===
    "true";

const AGREEMENT_SKIPPED_BUCKET = "uat-agreement-storage-skipped";

if (AGREEMENT_STORAGE_SKIPPED) {
  console.warn(
    "Agreement PDF storage is DISABLED (APP_ENV=uat, SKIP_AGREEMENT_STORAGE=true). PDFs are not stored and accept-invite does not verify upload."
  );
}

const s3 = new S3Client({
  region: AGREEMENT_S3_REGION,
});

module.exports = {
  s3,
  AGREEMENT_S3_REGION,
  AGREEMENT_S3_BUCKET,
  AGREEMENT_STORAGE_SKIPPED,
  AGREEMENT_SKIPPED_BUCKET,
};