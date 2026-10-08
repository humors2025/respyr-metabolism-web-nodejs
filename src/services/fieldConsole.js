'use strict';

/*
|--------------------------------------------------------------------------
| Field Console CRM — the US field team's gym pipeline
|--------------------------------------------------------------------------
| A port of Field Console/crm.py (the file-backed store the console ran on
| locally) onto MySQL, migration 007. The JSON it returns is the same shape
| crm.py returned, so the console's screens don't change — only where they
| save.
|
| Current state lives in fc_cards / fc_day_plans / fc_plan_stops /
| fc_place_checks / fc_markets / fc_reps / fc_board. History lives in
| fc_events, which is append-only: every card change inserts its event in the
| same transaction as the change.
|
| Dates: timestamps are stored as UTC DATETIME(3) and returned as ISO strings
| ("2026-10-06T14:29:26+00:00"); days are the rep's calendar day in their
| market's time zone, returned as "YYYY-MM-DD".
*/

const pool = require('../config/db');

class FieldError extends Error {
  constructor(message) {
    super(message);
    this.status = 400;
  }
}
const bad = (msg) => { throw new FieldError(msg); };

/* ------------------------------------------------------------ the board */

const DEFAULT_BOARD = {
  columns: [
    { key: 'planned', label: 'Planned', subs: [], fields: [] },
    {
      key: 'visited', label: 'Visited', fields: ['contact', 'role', 'phone', 'email'],
      // Keys are fixed (history uses them); the front-desk-manager rung came
      // later, so it is key 'fdm' shown as L3 and the old L3–L5 read L4–L6.
      subs: [
        { key: 'l1', label: 'L1 — Nobody to talk to' },
        { key: 'l2', label: 'L2 — Front desk only' },
        { key: 'trn', label: 'L3 — Talked to a trainer' },
        { key: 'fdm', label: 'L4 — Met the front desk manager' },
        { key: 'l3', label: 'L5 — Met the owner' },
        { key: 'l4', label: 'L6 — Demoed the device' },
        { key: 'l5', label: 'L7 — Owner said yes' },
      ],
    },
    { key: 'qr', label: 'QR up', subs: [], unlock: true, fields: ['qr_where', 'device_given', 'incentive'] },
    { key: 'stripe', label: 'Stripe onboarded', subs: [], fields: ['contact', 'email', 'partner_code'] },
    { key: 'sales', label: 'Sales', subs: [], fields: ['contact', 'phone', 'email', 'devices_sold', 'sales_amount'] },
  ],
};

const DEAD = ['', 'closed', 'moved'];

// What a save may set. Same list as crm.py FIELDS.
const FIELDS = [
  'col', 'sub', 'dead',
  'contact', 'role', 'phone', 'email', 'notes',
  'next_action', 'next_date', 'rep',
  'qr_where', 'device_given', 'incentive', 'incentive_note',
  'name', 'address', 'city', 'metro', 'kind', 'via', 'lat', 'lon',
  'photo', 'rating', 'reviews', 'g_type', 'hours', 'verified',
  'confirm',
  'plan_id', 'plan_date', 'plan_stop',
  'devices_sold', 'sales_amount', 'partner_code', 'ref_name', 'ref_role', 'ref_phone', 'ref_via', 'g_phone',
];

// Fields whose change is worth a line in the card's history.
const TRACKED = ['col', 'sub', 'dead', 'contact', 'role', 'phone', 'email', 'plan_date',
  'devices_sold', 'sales_amount', 'partner_code', 'ref_name', 'ref_role', 'ref_phone', 'ref_via',
  'next_action', 'next_date', 'qr_where', 'device_given', 'incentive',
  'name', 'address', 'city', 'via'];

const MAX_LEN = 2000;

/* ------------------------------------------------------------ small helpers */

const str = (v) => (v === null || v === undefined ? '' : String(v));

/* A phone as +<country><number>. Ten digits with no code is US/Canada. */
function phoneE164(v) {
  v = str(v).trim();
  if (!v) return '';
  let d = v.replace(/\D/g, '');
  if (v.startsWith('+') || v.startsWith('00')) {
    if (v.startsWith('00')) d = d.slice(2);
  } else if (d.length === 10) {
    d = '1' + d;
  } else if (!(d.length === 11 && d.startsWith('1'))) {
    bad(`phone needs a country code, e.g. +1 956 555 0123: ${v}`);
  }
  if (d.length < 8 || d.length > 15) bad(`that doesn't look like a phone number: ${v}`);
  return '+' + d;
}

const isDay = (v) => /^\d{4}-\d{2}-\d{2}$/.test(v) && !Number.isNaN(Date.parse(v + 'T00:00:00Z'))
  && new Date(v + 'T00:00:00Z').toISOString().slice(0, 10) === v;

/* UTC now, as stored ("2026-10-06 14:29:26.123") and as returned (ISO). */
const sqlNow = () => new Date().toISOString().replace('T', ' ').replace('Z', '');
const isoOf = (sql) => (sql ? sql.replace(' ', 'T').slice(0, 19) + '+00:00' : '');
const sqlOfIso = (iso) => new Date(iso).toISOString().replace('T', ' ').replace('Z', '');

/* The calendar day in a time zone, for a UTC instant. */
function dayIn(tz, when = new Date()) {
  try {
    return new Intl.DateTimeFormat('en-CA', { timeZone: tz || 'America/Chicago', year: 'numeric', month: '2-digit', day: '2-digit' }).format(when);
  } catch {
    return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Chicago', year: 'numeric', month: '2-digit', day: '2-digit' }).format(when);
  }
}
const shiftDay = (d, n) => { const t = new Date(d + 'T12:00:00Z'); t.setUTCDate(t.getUTCDate() + n); return t.toISOString().slice(0, 10); };

/* DATE and DATETIME come back as the strings MySQL holds, never as JS Dates
   in the server's local zone. */
const typeCast = (field, next) => {
  if (field.type === 'DATE' || field.type === 'DATETIME' || field.type === 'TIMESTAMP') return field.string();
  // JSON columns report the binary charset; newer mysql2 then decodes them as
  // latin1 ("—" read back as "â", "José" as "JosÃ©"). They hold UTF-8.
  if (field.type === 'JSON') { const s = field.string('utf8'); return s === null ? null : JSON.parse(s); }
  return next();
};
const q = (conn, sql, params = []) => conn.query({ sql, typeCast }, params).then(([rows]) => rows);

async function tx(fn) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const out = await fn(conn);
    await conn.commit();
    return out;
  } catch (e) {
    try { await conn.rollback(); } catch { /* the original error matters more */ }
    throw e;
  } finally {
    conn.release();
  }
}

/* ------------------------------------------------------------ team */

const DEFAULT_TEAM = {
  markets: [
    { key: 'rgv', name: 'Rio Grande Valley', metros: ['Rio Grande Valley'], tz: 'America/Chicago', tz_label: 'Texas', cc: '1' },
    { key: 'hou', name: 'Houston', metros: ['Houston Metro'], tz: 'America/Chicago', tz_label: 'Texas', cc: '1' },
  ],
  reps: [
    { key: 'derek', name: 'Derek', role: 'rep', market: 'rgv', phone: '', base: { lat: 26.2419032, lon: -97.5854566, label: '714 Harris Rd, Rio Hondo' } },
    { key: 'evan', name: 'Evan', role: 'rep', market: 'hou', phone: '', base: null },
    { key: 'ishan', name: 'Ishan', role: 'manager', market: '', phone: '', base: null },
  ],
};

async function team(conn = pool) {
  const markets = await q(conn, 'SELECT * FROM fc_markets ORDER BY position, `key`');
  const reps = await q(conn, 'SELECT * FROM fc_reps WHERE active = 1 ORDER BY position, `key`');
  if (!markets.length || !reps.length) return JSON.parse(JSON.stringify(DEFAULT_TEAM));
  return {
    markets: markets.map((m) => ({ key: m.key, name: m.name, metros: m.metros || [], tz: m.tz, tz_label: m.tz_label, cc: m.cc })),
    reps: reps.map((r) => ({
      key: r.key, name: r.name, role: r.role, market: r.market_key || '', phone: r.phone || '',
      base: r.base_lat !== null && r.base_lat !== undefined ? { lat: +r.base_lat, lon: +r.base_lon, label: r.base_label || '' } : null,
      user_id: r.user_id || null,
    })),
  };
}

/* The time zone a rep works in: their market's. Unknown rep, the first market. */
function tzOf(t, rep) {
  const r = t.reps.find((x) => x.key === rep);
  const m = (r && t.markets.find((x) => x.key === r.market)) || t.markets[0];
  return (m && m.tz) || 'America/Chicago';
}

const KEY = /^[a-z0-9][a-z0-9-]{0,30}$/;

async function saveTeam(payload) {
  if (!payload || typeof payload !== 'object') bad('team must be an object');
  const markets = [];
  for (const m of payload.markets || []) {
    const key = str(m.key).trim().toLowerCase();
    if (!KEY.test(key)) bad(`market key must be short lowercase letters/digits: ${key}`);
    const tz = str(m.tz).trim();
    try { new Intl.DateTimeFormat('en', { timeZone: tz }); } catch { bad(`unknown time zone for ${key}: ${tz}`); }
    const metros = (m.metros || []).map((x) => str(x).trim()).filter(Boolean);
    if (!metros.length) bad(`market ${key} needs at least one metro`);
    markets.push({ key, name: str(m.name || key).trim().slice(0, 60), metros, tz,
      tz_label: str(m.tz_label).trim().slice(0, 30), cc: (str(m.cc || '1').replace(/\D/g, '') || '1').slice(0, 4) });
  }
  if (!markets.length) bad('at least one market is needed');
  const mkeys = new Set(markets.map((m) => m.key));
  if (mkeys.size !== markets.length) bad('two markets share a key');
  const reps = [];
  for (const r of payload.reps || []) {
    const key = str(r.key).trim().toLowerCase();
    if (!KEY.test(key)) bad(`rep key must be short lowercase letters/digits: ${key}`);
    const role = r.role === 'manager' ? 'manager' : 'rep';
    const mk = str(r.market);
    if (mk && !mkeys.has(mk)) bad(`${key} is in a market that doesn't exist: ${mk}`);
    if (role === 'rep' && !mk) bad(`${key} needs a market`);
    let base = null;
    if (r.base) {
      const lat = Number(r.base.lat), lon = Number(r.base.lon);
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) bad(`${key}'s starting point needs a lat and lon`);
      if (lat < -90 || lat > 90 || lon < -180 || lon > 180) bad(`${key}'s starting point is off the map`);
      base = { lat, lon, label: str(r.base.label).trim().slice(0, 120) };
    }
    const user = r.user_id ? str(r.user_id).trim().toLowerCase().slice(0, 150) : null;
    reps.push({ key, name: str(r.name || key).trim().slice(0, 40), role, market: mk, phone: phoneE164(r.phone), base, user_id: user });
  }
  if (!reps.length) bad('at least one person is needed');
  if (new Set(reps.map((r) => r.key)).size !== reps.length) bad('two people share a key');

  return tx(async (conn) => {
    // Reps that leave the team are deactivated, not deleted: their cards and
    // history still name them.
    await q(conn, 'UPDATE fc_reps SET active = 0, market_key = NULL');
    await q(conn, 'DELETE FROM fc_markets WHERE `key` NOT IN (?)', [[...mkeys]]);
    for (const [i, m] of markets.entries()) {
      await q(conn, `INSERT INTO fc_markets (\`key\`, name, metros, tz, tz_label, cc, position) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE name = VALUES(name), metros = VALUES(metros), tz = VALUES(tz), tz_label = VALUES(tz_label), cc = VALUES(cc), position = VALUES(position)`,
      [m.key, m.name, JSON.stringify(m.metros), m.tz, m.tz_label, m.cc, i]);
    }
    for (const [i, r] of reps.entries()) {
      await q(conn, `INSERT INTO fc_reps (\`key\`, user_id, name, role, market_key, phone, base_lat, base_lon, base_label, position, active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        ON DUPLICATE KEY UPDATE user_id = VALUES(user_id), name = VALUES(name), role = VALUES(role), market_key = VALUES(market_key),
          phone = VALUES(phone), base_lat = VALUES(base_lat), base_lon = VALUES(base_lon), base_label = VALUES(base_label),
          position = VALUES(position), active = 1`,
      [r.key, r.user_id, r.name, r.role, r.market || null, r.phone, r.base ? r.base.lat : null, r.base ? r.base.lon : null, r.base ? r.base.label : '', i]);
    }
    return team(conn);
  });
}

/* ------------------------------------------------------------ board */

async function board(conn = pool) {
  const rows = await q(conn, 'SELECT `columns` FROM fc_board WHERE id = 1');
  return rows.length && rows[0].columns && rows[0].columns.length ? { columns: rows[0].columns } : DEFAULT_BOARD;
}

async function saveBoard(cfg) {
  const cols = cfg && cfg.columns;
  if (!Array.isArray(cols) || !cols.length) bad('a board needs at least one column');
  const cur = await board();
  const want = cur.columns.map((c) => c.key).sort().join('|');
  if (cols.map((c) => str(c.key)).sort().join('|') !== want) bad('stages can be renamed, not added, removed or re-keyed');
  const clean = cols.map((c) => {
    const key = str(c.key).trim(), label = str(c.label).trim();
    if (!key || !label) bad('every column needs a key and a label');
    const subs = (c.subs || []).map((s) => ({ key: str(s.key).trim().slice(0, 40), label: str(s.label).trim().slice(0, 120) })).filter((s) => s.key && s.label);
    return { key: key.slice(0, 40), label: label.slice(0, 60), subs, fields: (c.fields || []).map((f) => str(f).slice(0, 40)), ...(c.unlock ? { unlock: true } : {}) };
  });
  await q(pool, 'INSERT INTO fc_board (id, `columns`) VALUES (1, ?) ON DUPLICATE KEY UPDATE `columns` = VALUES(`columns`)', [JSON.stringify(clean)]);
  return { columns: clean };
}

/* ------------------------------------------------------------ cards */

// Card fields stored as plain text columns, same name in the record.
const TEXT_COLS = ['col', 'sub', 'dead', 'contact', 'role', 'phone', 'email', 'next_action',
  'qr_where', 'device_given', 'incentive_note', 'name', 'address', 'city', 'metro', 'kind', 'via',
  'photo', 'rating', 'reviews', 'g_type', 'hours', 'verified', 'confirm', 'plan_id', 'last_note', 'removed_by',
  'partner_code', 'ref_name', 'ref_role', 'ref_phone', 'ref_via', 'g_phone'];

/* A row, read back as the record crm.py returned. Empty values are left out,
   as they were absent in crm.json. */
function recOf(row) {
  if (!row) return null;
  const r = { place_id: row.place_id };
  for (const k of TEXT_COLS) if (row[k] !== null && row[k] !== undefined && row[k] !== '') r[k] = String(row[k]);
  if (row.rep_key) r.rep = row.rep_key;
  if (row.next_date) r.next_date = row.next_date;
  if (row.plan_date) r.plan_date = row.plan_date;
  if (row.plan_stop !== null && row.plan_stop !== undefined) r.plan_stop = String(row.plan_stop);
  if (row.incentive !== null && row.incentive !== undefined) r.incentive = String(+row.incentive);
  if (row.devices_sold !== null && row.devices_sold !== undefined) r.devices_sold = String(row.devices_sold);
  if (row.sales_amount !== null && row.sales_amount !== undefined) r.sales_amount = String(+row.sales_amount);
  if (row.lat !== null && row.lat !== undefined) r.lat = String(+row.lat);
  if (row.lon !== null && row.lon !== undefined) r.lon = String(+row.lon);
  if (row.first_visit) r.first_visit = row.first_visit;
  if (row.last_visit) r.last_visit = row.last_visit;
  if (row.col_since) r.col_since = isoOf(row.col_since);
  if (row.last_note_at) r.last_note_at = isoOf(row.last_note_at);
  if (row.removed) {
    r.removed = 'yes';
    r.removed_reason = row.removed_reason || '';
    r.removed_at = isoOf(row.removed_at);
  }
  r.touches = row.touches;
  if (row.notes_n) r.notes_n = row.notes_n;
  r.created = isoOf(row.created_at);
  r.updated = isoOf(row.updated_at);
  return r;
}

async function writeCard(conn, rec) {
  const num = (v) => (str(v).trim() === '' ? null : Number(str(v).replace(/[$,]/g, '')));
  const day = (v) => (isDay(str(v)) ? str(v) : null);
  const ts = (v) => (v ? sqlOfIso(v) : null);
  const row = {
    place_id: rec.place_id, rep_key: str(rec.rep).slice(0, 32),
    next_date: day(rec.next_date), plan_date: day(rec.plan_date),
    plan_stop: str(rec.plan_stop).trim() === '' ? null : parseInt(rec.plan_stop, 10) || null,
    incentive: num(rec.incentive), lat: num(rec.lat), lon: num(rec.lon),
    devices_sold: num(rec.devices_sold) === null || Number.isNaN(num(rec.devices_sold)) ? num(rec.devices_sold) : Math.max(0, Math.round(num(rec.devices_sold))),
    sales_amount: num(rec.sales_amount),
    removed: rec.removed ? 1 : 0, removed_reason: rec.removed ? str(rec.removed_reason) : null,
    removed_at: rec.removed ? ts(rec.removed_at) : null,
    col_since: ts(rec.col_since), first_visit: day(rec.first_visit), last_visit: day(rec.last_visit),
    touches: +rec.touches || 0, notes_n: +rec.notes_n || 0, last_note_at: ts(rec.last_note_at),
    created_at: ts(rec.created) || sqlNow(), updated_at: ts(rec.updated) || sqlNow(),
  };
  for (const k of TEXT_COLS) row[k] = str(rec[k]);
  if (!DEAD.includes(row.dead)) row.dead = '';
  if (!['', 'yes', 'no'].includes(row.device_given)) row.device_given = '';
  if (Number.isNaN(row.incentive)) bad(`incentive must be a number: ${rec.incentive}`);
  if (Number.isNaN(row.devices_sold)) bad(`devices sold must be a number: ${rec.devices_sold}`);
  if (Number.isNaN(row.sales_amount)) bad(`sales must be a number: ${rec.sales_amount}`);
  const cols = Object.keys(row);
  await q(conn, `INSERT INTO fc_cards (${cols.map((c) => '`' + c + '`').join(', ')}) VALUES (${cols.map(() => '?').join(', ')})
    ON DUPLICATE KEY UPDATE ${cols.filter((c) => c !== 'place_id').map((c) => '`' + c + '` = VALUES(`' + c + '`)').join(', ')}`,
  cols.map((c) => row[c]));
}

async function getCard(conn, placeId, lock = false) {
  const rows = await q(conn, `SELECT * FROM fc_cards WHERE place_id = ?${lock ? ' FOR UPDATE' : ''}`, [placeId]);
  return rows.length ? recOf(rows[0]) : null;
}

async function allRecords(conn = pool) {
  const rows = await q(conn, 'SELECT * FROM fc_cards');
  const out = {};
  for (const row of rows) out[row.place_id] = recOf(row);
  return out;
}

/* ------------------------------------------------------------ events */

async function addEvent(conn, e) {
  const known = ['type', 'place_id', 'rep', 'at', 'on', 'col', 'sub', 'from', 'from_sub', 'text', 'reason', 'changes'];
  const extra = {};
  for (const [k, v] of Object.entries(e)) if (!known.includes(k) && v !== undefined) extra[k] = v;
  await q(conn, `INSERT INTO fc_events (place_id, type, rep_key, at, on_day, col, sub, from_col, from_sub, text, reason, changes, extra)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  [e.place_id, e.type, str(e.rep), sqlOfIso(e.at), e.on, e.col ?? null, e.sub ?? null, e.from ?? null, e.from_sub ?? null,
    e.text ?? null, e.reason ?? null, e.changes ? JSON.stringify(e.changes) : null, Object.keys(extra).length ? JSON.stringify(extra) : null]);
}

function eventOf(row) {
  const e = { ...(row.extra || {}), type: row.type, place_id: row.place_id, rep: row.rep_key, at: isoOf(row.at), on: row.on_day };
  if (row.col !== null) e.col = row.col;
  if (row.sub !== null) e.sub = row.sub;
  if (row.from_col !== null) e.from = row.from_col;
  if (row.from_sub !== null) e.from_sub = row.from_sub;
  if (row.text !== null) e.text = row.text;
  if (row.reason !== null) e.reason = row.reason;
  if (row.changes) e.changes = row.changes;
  return e;
}

/* Most recent first. What the manager reads to see the day. */
async function log(limit = 400, rep = null) {
  limit = Math.max(1, Math.min(parseInt(limit, 10) || 400, 100000));
  const rows = rep
    ? await q(pool, 'SELECT * FROM fc_events WHERE rep_key = ? ORDER BY at DESC, id DESC LIMIT ?', [rep, limit])
    : await q(pool, 'SELECT * FROM fc_events ORDER BY at DESC, id DESC LIMIT ?', [limit]);
  return rows.map(eventOf);
}

async function history(placeId) {
  const rows = await q(pool, 'SELECT * FROM fc_events WHERE place_id = ? ORDER BY at DESC, id DESC', [str(placeId)]);
  return rows.map(eventOf);
}

/* ------------------------------------------------------------ saving */

function clean(payload) {
  const out = {};
  for (const k of FIELDS) {
    const v = payload[k];
    if (v === null || v === undefined) continue;
    const s = String(v).trim();
    if (s) out[k] = s.slice(0, MAX_LEN);
  }
  return out;
}

/* Upsert one card, inside a transaction the caller may already hold. */
async function saveIn(conn, placeId, payload, t) {
  placeId = str(placeId).trim();
  if (!placeId) bad('place_id is required');
  const rec = clean(payload);
  if (rec.email) {
    rec.email = rec.email.toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(rec.email)) bad(`that email doesn't look right: ${rec.email}`);
  }
  if (rec.phone) rec.phone = phoneE164(rec.phone);
  if (rec.ref_phone) rec.ref_phone = phoneE164(rec.ref_phone);
  if (rec.g_phone) rec.g_phone = phoneE164(rec.g_phone);
  const repForDay = str(payload.rep);
  const today = dayIn(tzOf(t, repForDay));
  let on = null;
  if (str(payload.on).trim()) {
    on = str(payload.on).trim();
    if (!isDay(on)) bad(`not a real date: ${on}`);
    if (on > today) bad(`a visit can't be in the future: ${on}`);
  }
  if (rec.dead && !DEAD.includes(rec.dead)) bad(`unknown dead marker: ${rec.dead}`);
  for (const k of ['next_date', 'plan_date']) if (rec[k] && !isDay(rec[k])) bad(`not a real date: ${rec[k]}`);

  const b = await board(conn);
  const order = b.columns.map((c) => c.key);
  const prev = (await getCard(conn, placeId, true)) || {};
  const col = rec.col || prev.col || 'planned';
  if (!order.includes(col)) bad(`unknown column: ${col}`);
  if (prev.col && order.includes(prev.col) && Math.abs(order.indexOf(col) - order.indexOf(prev.col)) > 1) {
    bad(`stages move one at a time: ${prev.col} can't go straight to ${col}`);
  }
  rec.col = col;
  if (prev.col && col !== prev.col && !('sub' in payload)) rec.sub = '';

  const note = rec.notes; delete rec.notes;
  const merged = { ...prev, ...rec };
  for (const k of FIELDS) {
    if (k in payload && k !== 'col' && k !== 'notes' && !str(payload[k]).trim()) merged[k] = '';
  }
  const now = new Date().toISOString().slice(0, 19) + '+00:00';
  merged.place_id = placeId;
  merged.updated = now;
  if (!merged.created) merged.created = now;
  merged.touches = (+prev.touches || 0) + 1;
  const moved = prev.col !== merged.col || str(prev.sub) !== str(merged.sub);
  if (moved || !merged.col_since) merged.col_since = now;
  if (note) {
    merged.notes_n = (+prev.notes_n || 0) + 1;
    merged.last_note = note.slice(0, 280);
    merged.last_note_at = now;
  }
  const day = on || dayIn(tzOf(t, str(merged.rep)));
  // Putting a card on a day (a revisit) is a plan, not a visit.
  const planOnly = Object.keys(payload).filter((k) => !['place_id', 'rep', 'on'].includes(k))
    .every((k) => ['plan_id', 'plan_date', 'plan_stop', 'next_date'].includes(k));
  if (merged.col !== 'planned' && !planOnly) {
    if (!merged.first_visit || day < merged.first_visit) merged.first_visit = day;
    if (day >= str(merged.last_visit)) merged.last_visit = day;
  }
  const changes = {};
  for (const k of TRACKED) {
    const a = str(prev[k]), z = str(merged[k]);
    if (a !== z) changes[k] = [a, z];
  }
  if (Object.keys(prev).length && !note && FIELDS.filter((k) => k !== 'notes').every((k) => str(prev[k]) === str(merged[k]))) {
    return prev;
  }
  await writeCard(conn, merged);

  const entry = {};
  for (const [k, v] of Object.entries(rec)) if (TRACKED.includes(k) || k === 'rep') entry[k] = v;
  Object.assign(entry, {
    place_id: placeId, at: now, on: day, col: merged.col, sub: str(merged.sub),
    type: !Object.keys(prev).length ? 'added' : moved ? 'move' : 'edit',
    from: prev.col ?? null, from_sub: prev.sub ?? null, changes,
  });
  // A save that only renumbers a day is not news; history keeps what a person would read back.
  if (entry.type !== 'edit' || Object.keys(changes).length) await addEvent(conn, entry);
  if (note) await addEvent(conn, { type: 'note', place_id: placeId, at: now, on: day, rep: str(rec.rep), text: note, col: merged.col });
  return getCard(conn, placeId);
}

async function save(placeId, payload) {
  return tx(async (conn) => saveIn(conn, placeId, payload, await team(conn)));
}

/* A dated note. Notes are never edited or replaced. */
/* Fix the day one history line is filed under (a visit logged on the 7th that
   happened on the 1st). The line keeps its timestamp, gets the right day, and
   a "redated" line records who changed it from what to what. The card's first
   and last visit and days-in-stage are worked out again from the history. */
async function redate(placeId, at, type, on, rep = '') {
  placeId = str(placeId).trim();
  if (!['added', 'move', 'edit', 'note'].includes(type)) bad('only visits, moves, edits and notes have a day to fix');
  return tx(async (conn) => {
    const t = await team(conn);
    if (!isDay(str(on)) || on > dayIn(tzOf(t, rep))) bad(`pick a real day, not in the future: ${on}`);
    const [ev] = await q(conn, 'SELECT id, on_day, col FROM fc_events WHERE place_id = ? AND at = ? AND type = ? LIMIT 1 FOR UPDATE',
      [placeId, sqlOfIso(at), type]);
    if (!ev) bad("that history line wasn't found");
    const was = str(ev.on_day instanceof Date ? ev.on_day.toISOString().slice(0, 10) : ev.on_day).slice(0, 10);
    if (was !== on) {
      await q(conn, 'UPDATE fc_events SET on_day = ? WHERE id = ?', [on, ev.id]);
      const now = new Date().toISOString().slice(0, 19) + '+00:00';
      await addEvent(conn, { type: 'redated', place_id: placeId, at: now, on: dayIn(tzOf(t, rep)), rep, col: ev.col,
        target_at: at, target_type: type, was, now: on });
      const [d] = await q(conn, `SELECT MIN(on_day) AS f, MAX(on_day) AS l FROM fc_events
        WHERE place_id = ? AND type IN ('added','move','edit','note') AND col IS NOT NULL AND col NOT IN ('', 'planned')`, [placeId]);
      const c = await getCard(conn, placeId, true);
      const [mv] = await q(conn, `SELECT on_day FROM fc_events WHERE place_id = ? AND type IN ('move','added') AND col = ?
        ORDER BY at DESC LIMIT 1`, [placeId, c ? c.col : '']);
      if (c && d && d.f) {
        const iso = (v) => (v instanceof Date ? v.toISOString().slice(0, 10) : str(v).slice(0, 10));
        await q(conn, 'UPDATE fc_cards SET first_visit = ?, last_visit = ?, col_since = COALESCE(?, col_since) WHERE place_id = ?',
          [iso(d.f), iso(d.l), mv ? `${iso(mv.on_day)} 12:00:00` : null, placeId]);
      }
    }
    return getCard(conn, placeId);
  });
}

async function addNote(placeId, text, rep = '', on = null) {
  placeId = str(placeId).trim();
  text = str(text).trim().slice(0, MAX_LEN);
  if (!placeId) bad('place_id is required');
  if (!text) bad('a note needs some text');
  return tx(async (conn) => {
    const t = await team(conn);
    const today = dayIn(tzOf(t, rep));
    if (on && (!isDay(on) || on > today)) bad(`not a usable date: ${on}`);
    const now = new Date().toISOString().slice(0, 19) + '+00:00';
    let rec = await getCard(conn, placeId, true);
    if (!rec) rec = { place_id: placeId, col: 'planned', created: now, col_since: now, touches: 0, rep };
    rec.notes_n = (+rec.notes_n || 0) + 1;
    rec.last_note = text.slice(0, 280);
    rec.last_note_at = now;
    rec.updated = now;
    await writeCard(conn, rec);
    await addEvent(conn, { type: 'note', place_id: placeId, at: now, on: on || today, rep, text, col: rec.col });
    return getCard(conn, placeId);
  });
}

/* Take a card out of the CRM or put it back. Nothing is deleted. */
async function setRemoved(placeId, removed, reason = '', rep = '') {
  placeId = str(placeId).trim();
  reason = str(reason).trim().slice(0, MAX_LEN);
  if (!placeId) bad('place_id is required');
  if (removed && !reason) bad("say why it's being removed");
  return tx(async (conn) => {
    const t = await team(conn);
    const rec = await getCard(conn, placeId, true);
    if (!rec) bad("that card isn't in the CRM");
    if (Boolean(rec.removed) === Boolean(removed)) return rec;
    const now = new Date().toISOString().slice(0, 19) + '+00:00';
    if (removed) {
      Object.assign(rec, { removed: 'yes', removed_reason: reason, removed_at: now, removed_by: rep });
      // Discarded comes off any day it was on; the rest of that day renumbers.
      if (rec.plan_id) {
        const plans = await q(conn, 'SELECT DISTINCT plan_id FROM fc_plan_stops WHERE place_id = ?', [placeId]);
        for (const { plan_id: id } of plans) {
          const left = (await q(conn, 'SELECT place_id FROM fc_plan_stops WHERE plan_id = ? ORDER BY position', [id])).map((r) => r.place_id).filter((x) => x !== placeId);
          await writeStops(conn, id, left);
          if (!left.length) await q(conn, 'DELETE FROM fc_day_plans WHERE id = ?', [id]);
          else await renumber(conn, id, left);
        }
        Object.assign(rec, { plan_id: null, plan_date: null, plan_stop: null });
      }
    } else for (const k of ['removed', 'removed_reason', 'removed_at', 'removed_by']) delete rec[k];
    rec.updated = now;
    await writeCard(conn, rec);
    await addEvent(conn, { type: removed ? 'removed' : 'restored', place_id: placeId, at: now, on: dayIn(tzOf(t, rep)), rep, reason, col: rec.col });
    return getCard(conn, placeId);
  });
}

async function summary() {
  const b = await board();
  const cols = Object.fromEntries(b.columns.map((c) => [c.key, 0]));
  const rows = await q(pool, 'SELECT col, rep_key, dead, removed, incentive FROM fc_cards');
  const reps = {};
  let gone = 0, money = 0, removed = 0;
  for (const r of rows) {
    if (r.removed) { removed += 1; continue; }
    if (r.col in cols) cols[r.col] += 1;
    const k = r.rep_key || 'unassigned';
    reps[k] = (reps[k] || 0) + 1;
    if (r.dead) gone += 1;
    if (r.incentive !== null) money += +r.incentive;
  }
  return { cols, reps, total: rows.length - removed, removed, dead: gone, incentive_total: Math.round(money * 100) / 100 };
}

/* ------------------------------------------------------------ day plans */

async function plans(conn = pool) {
  const ps = await q(conn, 'SELECT * FROM fc_day_plans ORDER BY created_at DESC LIMIT 200');
  if (!ps.length) return [];
  const stops = await q(conn, 'SELECT * FROM fc_plan_stops WHERE plan_id IN (?) ORDER BY plan_id, position', [ps.map((p) => p.id)]);
  return ps.map((p) => ({
    id: p.id, name: p.name, rep: p.rep_key, date: p.plan_date, created: isoOf(p.created_at),
    stops: stops.filter((s) => s.plan_id === p.id).map((s) => s.place_id),
  }));
}

async function writeStops(conn, planId, list) {
  await q(conn, 'DELETE FROM fc_plan_stops WHERE plan_id = ?', [planId]);
  if (list.length) {
    await q(conn, 'INSERT INTO fc_plan_stops (plan_id, position, place_id) VALUES ?', [list.map((p, i) => [planId, i + 1, p])]);
  }
}

/* A day's route, put into the CRM in one transaction (see crm.py plan_day). */
async function planDay(payload) {
  const rep = str(payload.rep).trim().slice(0, 32);
  const date = str(payload.date).trim();
  if (!isDay(date)) bad('a day plan needs a date');
  if (!rep) bad('say who the plan is for');
  const stops = [];
  for (const x of payload.stops || []) { const s = str(x).trim().slice(0, 255); if (s && !stops.includes(s)) stops.push(s); }
  const pid = `${rep}:${date}`;
  const out = { added: 0, kept: 0, moved: 0, dropped: 0, revisits: 0 };
  await tx(async (conn) => {
    const t = await team(conn);
    const prevStops = (await q(conn, 'SELECT place_id FROM fc_plan_stops WHERE plan_id = ? ORDER BY position', [pid])).map((r) => r.place_id);
    for (const [i, place] of stops.entries()) {
      const c = await getCard(conn, place, true);
      if (c && c.removed) continue;
      if (c && c.col && c.col !== 'planned') {
        // A revisit: on the day like any stop, stage left alone.
        out.revisits += 1;
        if (c.plan_id !== pid || String(c.plan_stop) !== String(i + 1)) await saveIn(conn, place, { rep, plan_id: pid, plan_date: date, plan_stop: String(i + 1) }, t);
        continue;
      }
      if (!c) out.added += 1; else if (c.plan_id === pid) out.kept += 1; else out.moved += 1;
      const meta = (!c && payload.meta && payload.meta[place]) || {};
      const extra = {};
      for (const k of ['name', 'city', 'metro', 'lat', 'lon']) if (k in meta) extra[k] = meta[k];
      await saveIn(conn, place, { ...extra, col: 'planned', rep, plan_id: pid, plan_date: date, plan_stop: String(i + 1),
        next_date: date, next_action: (c && c.next_action) || 'Visit' }, t);
    }
    for (const place of prevStops) {
      if (stops.includes(place)) continue;
      const c = await getCard(conn, place, true);
      if (!c || c.plan_id !== pid) continue;
      const untouched = c.col === 'planned' && !c.first_visit && !(+c.notes_n) && !c.removed;
      const now = new Date().toISOString().slice(0, 19) + '+00:00';
      if (untouched) {
        await q(conn, 'DELETE FROM fc_cards WHERE place_id = ?', [place]);   // only ever planned: it leaves the CRM, its events stay
      } else {
        for (const k of ['plan_id', 'plan_date', 'plan_stop']) delete c[k];
        c.updated = now;
        await writeCard(conn, c);
      }
      out.dropped += 1;
      await addEvent(conn, { type: 'unplanned', place_id: place, at: now, on: dayIn(tzOf(t, rep)), rep, plan_date: date, col: c.col, left_crm: untouched });
    }
    // A gym is on one day at a time: moving it here takes it off the rep's other days.
    if (stops.length) {
      const others = await q(conn, 'SELECT s.plan_id, s.place_id FROM fc_plan_stops s JOIN fc_day_plans p ON p.id = s.plan_id WHERE p.rep_key = ? AND s.plan_id <> ? AND s.place_id IN (?)', [rep, pid, stops]);
      for (const planId of new Set(others.map((o) => o.plan_id))) {
        const left = (await q(conn, 'SELECT place_id FROM fc_plan_stops WHERE plan_id = ? ORDER BY position', [planId])).map((r) => r.place_id).filter((p) => !stops.includes(p));
        await writeStops(conn, planId, left);
        if (!left.length) await q(conn, 'DELETE FROM fc_day_plans WHERE id = ?', [planId]);
      }
      await q(conn, `INSERT INTO fc_day_plans (id, rep_key, plan_date, name) VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE name = VALUES(name)`, [pid, rep, date, str(payload.name || `Day plan ${date}`).slice(0, 120)]);
      await writeStops(conn, pid, stops);
    } else {
      await q(conn, 'DELETE FROM fc_day_plans WHERE id = ?', [pid]);
    }
  });
  out.plan = stops.length ? (await plans()).find((p) => p.id === pid) || null : null;
  return out;
}

/* One Planned card onto a day ('' = no day), at a position, renumbering both days. */
async function moveToDay(placeId, date, rep, at = null) {
  placeId = str(placeId).trim();
  rep = str(rep).trim().slice(0, 32);
  date = str(date).trim();
  if (date && !isDay(date)) bad(`not a real date: ${date}`);
  return tx(async (conn) => {
    const t = await team(conn);
    const c = await getCard(conn, placeId, true);
    if (!c) bad("that card isn't in the CRM");
    if (c.removed) bad('that card was removed; restore it first');
    const first = c.col === 'planned';   // otherwise a revisit: keeps its stage and its own next step
    const owner = rep || c.rep || '';
    const touched = await q(conn, 'SELECT DISTINCT p.id FROM fc_day_plans p JOIN fc_plan_stops s ON s.plan_id = p.id WHERE s.place_id = ? AND p.rep_key = ?', [placeId, owner]);
    for (const { id } of touched) {
      const left = (await q(conn, 'SELECT place_id FROM fc_plan_stops WHERE plan_id = ? ORDER BY position', [id])).map((r) => r.place_id).filter((p) => p !== placeId);
      await writeStops(conn, id, left);
      if (!left.length) await q(conn, 'DELETE FROM fc_day_plans WHERE id = ?', [id]);
      else await renumber(conn, id, left);
    }
    if (!date) return saveIn(conn, placeId, { plan_id: '', plan_date: '', plan_stop: '', ...(first ? { next_date: '' } : {}), rep: owner }, t);
    const pid = `${owner}:${date}`;
    await q(conn, 'INSERT IGNORE INTO fc_day_plans (id, rep_key, plan_date, name) VALUES (?, ?, ?, ?)', [pid, owner, date, `Day plan ${date}`]);
    const list = (await q(conn, 'SELECT place_id FROM fc_plan_stops WHERE plan_id = ? ORDER BY position', [pid])).map((r) => r.place_id);
    const i = at === null || at === undefined ? list.length : Math.max(0, Math.min(parseInt(at, 10) || 0, list.length));
    list.splice(i, 0, placeId);
    await writeStops(conn, pid, list);
    await renumber(conn, pid, list, placeId);
    return saveIn(conn, placeId, { plan_id: pid, plan_date: date, plan_stop: String(i + 1), ...(first ? { next_date: date } : {}), rep: owner }, t);
  });
}

/* Keep "Stop 3" true on every card of a day after the order changed. */
async function renumber(conn, planId, list, skip = null) {
  for (const [n, p] of list.entries()) {
    if (p === skip) continue;
    await q(conn, 'UPDATE fc_cards SET plan_stop = ? WHERE place_id = ? AND plan_id = ?', [n + 1, p, planId]);
  }
}

async function deletePlan(planId) {
  await q(pool, 'DELETE FROM fc_day_plans WHERE id = ?', [str(planId)]);
}

/* ------------------------------------------------------------ is it still there? */

const CHECK_DAYS = 7;

async function checks(ids = null) {
  const rows = ids
    ? (ids.length ? await q(pool, 'SELECT * FROM fc_place_checks WHERE place_id IN (?)', [ids]) : [])
    : await q(pool, 'SELECT * FROM fc_place_checks');
  const out = {};
  for (const r of rows) {
    out[r.place_id] = { status: r.status, name: r.name, at: isoOf(r.checked_at), on: r.checked_on };
    if (r.was) { out[r.place_id].was = r.was; out[r.place_id].changed_on = r.changed_on; }
  }
  return out;
}

async function staleChecks(ids, force = false) {
  if (force) return ids;
  const t = await team();
  const cut = shiftDay(dayIn(tzOf(t, '')), -CHECK_DAYS);
  const have = await checks(ids);
  return ids.filter((p) => !have[p] || str(have[p].on) < cut);
}

async function saveChecks(found) {
  const t = await team();
  const on = dayIn(tzOf(t, ''));
  return tx(async (conn) => {
    for (const [pid, v] of Object.entries(found)) {
      const prev = (await q(conn, 'SELECT status, was, changed_on FROM fc_place_checks WHERE place_id = ? FOR UPDATE', [pid]))[0];
      const status = v.status || 'UNKNOWN';
      let was = prev ? prev.was : null, changedOn = prev ? prev.changed_on : null;
      if (prev && prev.status && prev.status !== status) { was = prev.status; changedOn = on; }
      await q(conn, `INSERT INTO fc_place_checks (place_id, status, name, checked_at, checked_on, was, changed_on) VALUES (?, ?, ?, ?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE status = VALUES(status), name = VALUES(name), checked_at = VALUES(checked_at), checked_on = VALUES(checked_on), was = VALUES(was), changed_on = VALUES(changed_on)`,
      [pid, status, str(v.name).slice(0, 200), sqlNow(), on, was, changedOn]);
    }
  });
}

/* ------------------------------------------------------------ export */

async function exportCsv() {
  const cols = ['place_id', 'col', 'sub', 'dead', 'rep', 'contact', 'role', 'phone', 'email',
    'qr_where', 'device_given', 'incentive', 'next_action', 'next_date', 'notes', 'touches', 'created', 'updated'];
  const recs = Object.values(await allRecords()).sort((a, b) => str(b.updated).localeCompare(str(a.updated)));
  const cell = (v) => { const s = str(v); return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  return [cols.join(','), ...recs.map((r) => cols.map((c) => cell(r[c])).join(','))].join('\r\n') + '\r\n';
}

module.exports = {
  FieldError, phoneE164, dayIn,
  team, saveTeam, board, saveBoard,
  allRecords, save, addNote, redate, setRemoved, summary, log, history,
  plans, planDay, moveToDay, deletePlan,
  checks, staleChecks, saveChecks, exportCsv,
  writeCard, addEvent, tx, q,
};
