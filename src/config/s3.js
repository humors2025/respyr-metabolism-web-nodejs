"use strict";

const { S3Client } = require("@aws-sdk/client-s3");

const AGREEMENT_S3_REGION =
  process.env.AGREEMENT_S3_REGION || process.env.AWS_REGION || "us-west-2";

const AGREEMENT_S3_BUCKET = process.env.AGREEMENT_S3_BUCKET || "";

const s3 = new S3Client({
  region: AGREEMENT_S3_REGION,
});

module.exports = {
  s3,
  AGREEMENT_S3_REGION,
  AGREEMENT_S3_BUCKET,
};