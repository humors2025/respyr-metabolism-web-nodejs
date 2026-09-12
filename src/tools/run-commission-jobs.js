"use strict";

/**
 * Scheduler entry point for the commission programme.
 *
 *   node src/tools/run-commission-jobs.js breath-credits [--dry-run]
 *   node src/tools/run-commission-jobs.js payouts        [--dry-run] [--period-end=YYYY-MM-DD]
 *
 * Intended cadence:
 *   breath-credits  nightly   (credits subscriptions renewing in the next 36h)
 *   payouts         monthly   (1st of the month, pays entries from the month before)
 *
 * On AWS this is the handler for an EventBridge-scheduled Lambda; locally or
 * in cron it runs as a plain script. Exit code 1 if any item errored.
 */

require("dotenv").config();

const pool = require("../config/db");
const { runBreathCredits } = require("../services/breathCredits");
const { runPayouts } = require("../services/payoutRuns");

async function main(argv) {
  const job = argv[0];
  const dryRun = argv.includes("--dry-run");
  const periodEndArg = (argv.find((a) => a.startsWith("--period-end=")) || "").split("=")[1];

  let summary;
  if (job === "breath-credits") {
    summary = await runBreathCredits({ dryRun });
  } else if (job === "payouts") {
    summary = await runPayouts({
      dryRun,
      initiatedBy: "scheduler",
      periodEnd: periodEndArg ? `${periodEndArg}T00:00:00Z` : null,
    });
  } else {
    console.error("usage: run-commission-jobs.js <breath-credits|payouts> [--dry-run] [--period-end=YYYY-MM-DD]");
    return 2;
  }

  console.log(JSON.stringify({ job, dry_run: dryRun, ...summary }, null, 2));
  return summary.errors > 0 ? 1 : 0;
}

// Lambda handler: event = { job: "breath-credits" | "payouts", dryRun?: bool }
module.exports.handler = async (event = {}) => {
  const args = [event.job || "breath-credits"];
  if (event.dryRun) args.push("--dry-run");
  const code = await main(args);
  return { ok: code === 0, exit_code: code };
};

if (require.main === module) {
  main(process.argv.slice(2))
    .then(async (code) => { await pool.end(); process.exit(code); })
    .catch(async (err) => { console.error(err); await pool.end(); process.exit(1); });
}
