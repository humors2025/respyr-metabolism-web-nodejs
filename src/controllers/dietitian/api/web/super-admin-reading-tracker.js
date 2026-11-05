"use strict";

/**
 * POST /dietitian/api/web/super-admin-reading-tracker   (super_admin only)
 *
 * Super Admin › Client › Reading Tracker: for one calendar month, the days each
 * paid profile took a breath reading and the days they missed. Read-only; every
 * day is worked out from existing tables, nothing is stored.
 *
 * Who is listed: subscriptions with a successful payment above $0 in
 * payment_transactions (the Orders › Payments rows; fully refunded ones do not
 * count), read from referral_subscriptions, whose paid time
 * overlaps the month. test_… rows, never-paid subscriptions (incomplete*) and
 * BREATH_CREDIT_EXCLUDE_PROFILES are left out. A buyer with no linked app profile
 * is listed with linked=false and no days, since they cannot have readings yet.
 *
 * Which days count (a profile with several subscriptions gets all of them):
 *   from  the purchase date
 *   to    today, or the end of the paid period if that has passed, or the
 *         cancellation date of a cancelled subscription
 * Readings outside those days are not reported in taken_days.
 *
 * Reading days come from table_test_data, the same "tested on this date" check as
 * All Clients. Not reward_ledger: on prod some days with a test have no 'earn' row,
 * and they would show as missed. A reading's day and time are the ones stored on
 * the test, unconverted. Customers are all in the US and their tests cluster in
 * morning hours with almost none around midnight, which fits the phone's own clock.
 *
 * "Today" and purchase dates are US Pacific days, so a day only becomes missed once
 * it has ended across the mainland US. Today without a reading is pending_days. A
 * client further east can already be on the next date, so a reading dated up to
 * today in US Eastern still counts, and that next date is otherwise left blank.
 *
 * Body:  { month?: "YYYY-MM" (default this month), search?,
 *          sort?: "most_missed" | "most_taken" | "name",
 *          show?: "all" | "taken_today" | "pending_today" | "first_today" (first reading
 *          ever was today) | "first_month" (in this month) | "never" (no reading ever),
 *          page?, limit? }
 * The today filters and counts only have data while month is the current month.
 *
 * →      { status, month, today, days_in_month,
 *          summary: { paid_profiles, not_linked, taken_days, readings, missed_days, no_reading,
 *                         took_today, readings_today, first_today, first_month, never },
 *          (first_* and never count each profile once; never leaves out unlinked buyers)
 *          rows: [ { profile_id, linked, name, email, partner_code, plan_code,
 *                    subscription_status, purchased_on, taken_days: ["YYYY-MM-DD"],
 *                    reading_times: { "YYYY-MM-DD": ["HH:MM:SS"] } (every test on a taken
 *                    day, as stored), reading_count, missed_days: [...],
 *                    pending_days: [...], today_count, last_reading: "YYYY-MM-DD HH:MM:SS",
 *                    first_reading: "YYYY-MM-DD HH:MM:SS" (earliest test ever, even before
 *                    purchase) } ],
 *          pagination: { page, limit, total, total_pages } }
 *
 * summary covers the whole month, ignoring search and paging. Rows carry buyers'
 * names and emails, so every read is written to app_auth_logs.
 */

const pool = require("../../../../config/db");
const { BREATH_CREDIT_EXCLUDE_PROFILES } = require("../../../../config/stripe");
const { _helpers: H } = require("./admin-invite-trainer");
const { _helpers: O } = require("./super-admin-orders");

const US_PACIFIC = "America/Los_Angeles";
const US_EASTERN = "America/New_York";
const DAY_MS = 86400000;
const DEFAULT_LIMIT = 20;
const MAX_LIMIT = 100;
const MAX_SEARCH_LENGTH = 100;
const SORTS = ["most_missed", "most_taken", "name"];
const SHOW_FILTERS = ["all", "taken_today", "pending_today", "first_today", "first_month", "never"];
const RUNNING_STATUSES = new Set(["active", "trialing", "past_due"]);

const MONTH_RE = /^\d{4}-(0[1-9]|1[0-2])$/;

/** US calendar day ("YYYY-MM-DD") of a stored UTC DATETIME or a Date. */
function usDay(value, timeZone = US_PACIFIC) {
  const iso = O.toIso(value);
  if (!iso) return null;
  const parts = new Intl.DateTimeFormat("en-US", { timeZone, year: "numeric", month: "2-digit", day: "2-digit" })
    .formatToParts(new Date(iso));
  const part = (type) => parts.find((p) => p.type === type).value;
  return `${part("year")}-${part("month")}-${part("day")}`;
}

/** Last day of a "YYYY-MM" month. */
function monthEnd(month) {
  const [y, m] = month.split("-").map(Number);
  return new Date(Date.UTC(y, m, 0)).toISOString().slice(0, 10);
}

/** Each "YYYY-MM-DD" from `from` to `to`, inclusive. */
function eachDay(from, to) {
  const days = [];
  for (let t = Date.parse(`${from}T00:00:00Z`), end = Date.parse(`${to}T00:00:00Z`); t <= end; t += DAY_MS) {
    days.push(new Date(t).toISOString().slice(0, 10));
  }
  return days;
}

/** The US days this subscription's readings count on, as { from, to }, up to latestDay. */
function countedWindow(sub, latestDay) {
  const from = usDay(sub.created_at);
  if (!from) return null;

  const status = String(sub.status || "").toLowerCase();
  let to;
  if (status === "canceled" && sub.canceled_at) to = usDay(sub.canceled_at);
  else if (sub.current_period_end) to = usDay(sub.current_period_end);
  else to = RUNNING_STATUSES.has(status) ? latestDay : from;

  if (to > latestDay) to = latestDay;
  return to < from ? null : { from, to };
}

/**
 * Turn subscriptions plus reading days into one row per profile, for a month.
 * readingDays: Map(profile_id -> Map("YYYY-MM-DD" -> ["HH:MM:SS"])). history: Map(profile_id
 * -> { first, last }, "YYYY-MM-DD HH:MM:SS"). `today` is the US Pacific day, `latestDay` the US Eastern
 * day (the newest date a reading can carry). Exported for tests.
 */
function buildRows(subs, readingDays, history, month, today, latestDay = today) {
  const start = `${month}-01`;
  const end = monthEnd(month);
  const groups = new Map();

  for (const sub of subs) {
    const window = countedWindow(sub, latestDay);
    if (!window || window.from > end || window.to < start) continue;

    const profileId = sub.profile_id || null;
    const key = profileId || `unlinked:${sub.stripe_subscription_id}`;
    let group = groups.get(key);
    if (!group) {
      group = { profileId, latest: sub, purchasedOn: window.from, days: new Set() };
      groups.set(key, group);
    }
    if (new Date(sub.created_at) > new Date(group.latest.created_at)) group.latest = sub;
    if (window.from < group.purchasedOn) group.purchasedOn = window.from;

    const from = window.from > start ? window.from : start;
    const to = window.to < end ? window.to : end;
    for (const day of eachDay(from, to)) group.days.add(day);
  }

  return [...groups.values()].map(({ profileId, latest, purchasedOn, days }) => {
    const readings = (profileId && readingDays.get(profileId)) || new Map();
    const counted = [...days].sort();
    const linked = !!profileId;
    const seen = (profileId && history.get(profileId)) || {};
    const noReading = linked ? counted.filter((d) => !readings.has(d)) : [];
    const takenDays = linked ? counted.filter((d) => readings.has(d)) : [];
    return {
      profile_id: profileId,
      linked,
      name: latest.purchaser_name || null,
      email: latest.purchaser_email ? String(latest.purchaser_email).toLowerCase() : null,
      partner_code: null,
      plan_code: latest.plan_code || null,
      subscription_status: O.deriveSubscriptionStatus({
        subscription_status: latest.status,
        canceled_at: latest.canceled_at,
        current_period_end: latest.current_period_end,
      }),
      purchased_on: purchasedOn,
      taken_days: takenDays,
      reading_times: Object.fromEntries(takenDays.map((d) => [d, readings.get(d)])),
      reading_count: takenDays.reduce((n, d) => n + readings.get(d).length, 0),
      missed_days: noReading.filter((d) => d < today),
      pending_days: noReading.filter((d) => d === today),
      today_count: readings.has(today) && takenDays.includes(today) ? readings.get(today).length : 0,
      last_reading: seen.last || null,
      first_reading: seen.first || null,
    };
  });
}

/** Does a row belong under a `show` filter? Exported for tests. */
function matchesShow(row, show, month, today) {
  switch (show) {
    case "taken_today":
      return row.today_count > 0;
    case "pending_today":
      return row.pending_days.length > 0;
    case "first_today":
      return !!row.first_reading && row.first_reading.startsWith(today);
    case "first_month":
      return !!row.first_reading && row.first_reading.startsWith(month);
    case "never":
      return row.linked && !row.first_reading;
    default:
      return true;
  }
}

/** Sort rows in place. Buyers with no linked profile always go last. */
function sortRows(rows, sort) {
  const byName = (a, b) => String(a.name || a.email || "").localeCompare(String(b.name || b.email || ""));
  return rows.sort((a, b) => {
    if (a.linked !== b.linked) return a.linked ? -1 : 1;
    if (sort === "most_missed" && a.missed_days.length !== b.missed_days.length) {
      return b.missed_days.length - a.missed_days.length;
    }
    if (sort === "most_taken" && a.taken_days.length !== b.taken_days.length) {
      return b.taken_days.length - a.taken_days.length;
    }
    return byName(a, b);
  });
}

function summarize(rows, month, today) {
  const linked = rows.filter((r) => r.linked);
  return {
    paid_profiles: rows.length,
    not_linked: rows.length - linked.length,
    taken_days: linked.reduce((n, r) => n + r.taken_days.length, 0),
    readings: linked.reduce((n, r) => n + r.reading_count, 0),
    missed_days: linked.reduce((n, r) => n + r.missed_days.length, 0),
    no_reading: linked.filter((r) => r.taken_days.length === 0).length,
    took_today: linked.filter((r) => r.today_count > 0).length,
    readings_today: linked.reduce((n, r) => n + r.today_count, 0),
    first_today: rows.filter((r) => matchesShow(r, "first_today", month, today)).length,
    first_month: rows.filter((r) => matchesShow(r, "first_month", month, today)).length,
    never: rows.filter((r) => matchesShow(r, "never", month, today)).length,
  };
}

async function loadSubscriptions(end) {
  const excluded = BREATH_CREDIT_EXCLUDE_PROFILES;
  const [subs] = await pool.execute(
    `
      SELECT rs.stripe_subscription_id, rs.profile_id, rs.purchaser_name, rs.purchaser_email,
             rs.plan_code, rs.status, rs.created_at, rs.current_period_end, rs.canceled_at
      FROM referral_subscriptions rs
      WHERE LEFT(rs.stripe_subscription_id, 5) <> 'test_'
        AND rs.status NOT IN ('incomplete', 'incomplete_expired')
        AND rs.created_at <= ?
        AND EXISTS (
          SELECT 1 FROM payment_transactions pt
          WHERE pt.stripe_subscription_id = rs.stripe_subscription_id
            AND pt.status IN ('paid', 'partially_refunded')
            AND pt.amount_paid_minor > 0
        )
        ${excluded.length ? `AND (rs.profile_id IS NULL OR rs.profile_id NOT IN (${excluded.map(() => "?").join(",")}))` : ""}
    `,
    // created_at is UTC. The month's last US day ends the next morning UTC, so this keeps
    // every purchase in the month; buildRows drops the ones that fall in the next.
    [`${new Date(Date.parse(`${end}T00:00:00Z`) + DAY_MS).toISOString().slice(0, 10)} 23:59:59`, ...excluded]
  );
  return subs;
}

/** Days in [start, end] and the latest reading ever, per profile. */
async function loadReadings(profileIds, start, end) {
  if (profileIds.length === 0) return { readingDays: new Map(), history: new Map() };

  const marks = profileIds.map(() => "?").join(",");
  const [days] = await pool.execute(
    `
      SELECT profile_id, DATE_FORMAT(date_time, '%Y-%m-%d') AS day, DATE_FORMAT(date_time, '%H:%i:%s') AS time
      FROM table_test_data
      WHERE profile_id IN (${marks})
        AND date_time >= ? AND date_time < DATE_ADD(?, INTERVAL 1 DAY)
      ORDER BY date_time, test_id
    `,
    [...profileIds, start, end]
  );
  const [latest] = await pool.execute(
    `
      SELECT profile_id,
             DATE_FORMAT(MIN(date_time), '%Y-%m-%d %H:%i:%s') AS earliest,
             DATE_FORMAT(MAX(date_time), '%Y-%m-%d %H:%i:%s') AS latest
      FROM table_test_data
      WHERE profile_id IN (${marks})
      GROUP BY profile_id
    `,
    profileIds
  );

  const readingDays = new Map();
  for (const row of days) {
    if (!readingDays.has(row.profile_id)) readingDays.set(row.profile_id, new Map());
    const profileDays = readingDays.get(row.profile_id);
    if (!profileDays.has(row.day)) profileDays.set(row.day, []);
    profileDays.get(row.day).push(row.time);
  }
  return { readingDays, history: new Map(latest.map((row) => [row.profile_id, { first: row.earliest, last: row.latest }])) };
}

/** Fill partner_code on rows so the page can open the client's profile. */
async function attachPartnerCodes(rows) {
  const profileIds = rows.filter((r) => r.linked).map((r) => r.profile_id);
  if (profileIds.length === 0) return;
  const [found] = await pool.execute(
    `
      SELECT tc.profile_id, tc.dietician_id, aur.partner_code
      FROM table_clients tc
      LEFT JOIN table_dietician td ON td.dietician_id = tc.dietician_id
      LEFT JOIN app_user_roles aur ON LOWER(aur.user_id) = LOWER(td.email)
      WHERE tc.profile_id IN (${profileIds.map(() => "?").join(",")})
    `,
    profileIds
  );
  const codes = new Map(found.map((row) => [row.profile_id, row.partner_code || row.dietician_id || null]));
  for (const row of rows) {
    if (row.linked) row.partner_code = codes.get(row.profile_id) || null;
  }
}

const superAdminReadingTracker = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
  if (req.method !== "POST") return res.status(405).json({ status: false, ok: false, message: "Method not allowed" });

  const body = req.body && typeof req.body === "object" ? req.body : {};
  let resolved = null;

  try {
    resolved = await H.resolveActorFromToken(req, ["super_admin"]);
    if (resolved.error) return res.status(resolved.error.status).json({ status: false, ...resolved.error.body });

    const today = usDay(new Date());
    const latestDay = usDay(new Date(), US_EASTERN);
    const month = body.month == null || body.month === "" ? today.slice(0, 7) : String(body.month);
    if (!MONTH_RE.test(month)) {
      return res.status(422).json({ status: false, ok: false, message: "month must be YYYY-MM" });
    }
    const sort = body.sort == null || body.sort === "" ? SORTS[0] : String(body.sort);
    if (!SORTS.includes(sort)) {
      return res.status(422).json({ status: false, ok: false, message: `sort must be one of ${SORTS.join(", ")}` });
    }
    const show = body.show == null || body.show === "" ? SHOW_FILTERS[0] : String(body.show);
    if (!SHOW_FILTERS.includes(show)) {
      return res.status(422).json({ status: false, ok: false, message: `show must be one of ${SHOW_FILTERS.join(", ")}` });
    }
    const search = String(body.search || "").trim().slice(0, MAX_SEARCH_LENGTH).toLowerCase();
    const page = Math.max(1, parseInt(body.page, 10) || 1);
    const limit = Math.min(MAX_LIMIT, Math.max(1, parseInt(body.limit, 10) || DEFAULT_LIMIT));

    const start = `${month}-01`;
    const end = monthEnd(month);
    const subs = await loadSubscriptions(end);
    const profileIds = [...new Set(subs.map((s) => s.profile_id).filter(Boolean))];
    const { readingDays, history } = await loadReadings(profileIds, start, end);

    const rows = buildRows(subs, readingDays, history, month, today, latestDay);
    const summary = summarize(rows, month, today);
    const matching = rows.filter((r) => {
      if (!matchesShow(r, show, month, today)) return false;
      return !search || [r.name, r.email, r.profile_id].some((v) => v && v.toLowerCase().includes(search));
    });
    sortRows(matching, sort);

    const total = matching.length;
    const pageRows = matching.slice((page - 1) * limit, page * limit);
    await attachPartnerCodes(pageRows);

    await H.writeAuthLogSafe(req, {
      eventType: "super_admin_reading_tracker_viewed",
      userId: resolved.actorEmail,
      role: resolved.actor.role,
      partnerCode: null,
      identifier: resolved.actorEmail,
      success: true,
      failureReason: `month=${month}`,
    });

    return res.status(200).json({
      status: true,
      ok: true,
      month,
      today,
      days_in_month: Number(end.slice(8)),
      summary,
      rows: pageRows,
      pagination: { page, limit, total, total_pages: Math.max(1, Math.ceil(total / limit)) },
    });
  } catch (err) {
    console.error("SUPER_ADMIN_READING_TRACKER_ERROR:", { code: err?.code, message: err?.message });
    if (resolved && !resolved.error) {
      await H.writeAuthLogSafe(req, {
        eventType: "super_admin_reading_tracker_error",
        userId: resolved.actorEmail,
        role: resolved.actor.role,
        partnerCode: null,
        identifier: resolved.actorEmail,
        success: false,
        failureReason: String(err?.code || "internal_error"),
      });
    }
    return res.status(500).json({ status: false, ok: false, message: "Internal server error" });
  }
};

module.exports = {
  superAdminReadingTracker,
  _helpers: { usDay, US_EASTERN, monthEnd, countedWindow, buildRows, matchesShow, sortRows, summarize },
};
