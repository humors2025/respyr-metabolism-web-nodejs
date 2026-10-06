#!/usr/bin/env node
'use strict';

/*
| One-off: load the Field Console's local files into the migration-007 tables.
|
|   node database/seed/import-field-console.js "<path to Field Console>" \
|        --link derek=derek.lopez88@gmail.com --link evan=evan.gaudet@gmail.com \
|        [--replace] [--dry-run]
|
| Reads crm.json (cards), crm.log (history, every line), plans.json,
| checks.json, web/team.json and board.json if present. Refuses to run on a
| database that already has field cards unless --replace is given, which
| empties the fc_* tables first. Everything is one transaction: it all lands,
| or nothing does.
*/

require('dotenv').config();
const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');

const args = process.argv.slice(2);
const dir = args.find((a) => !a.startsWith('--') && !/^\w+=/.test(a));
const replace = args.includes('--replace');
const dry = args.includes('--dry-run');
const links = {};
args.forEach((a, i) => { if (a === '--link' && args[i + 1]) { const [k, v] = args[i + 1].split('='); links[k] = v.toLowerCase(); } });

if (!dir) { console.error('Usage: import-field-console.js <Field Console dir> [--link rep=email] [--replace] [--dry-run]'); process.exit(2); }
const read = (f, d) => { try { return JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')); } catch { return d; } };

const cards = read('crm.json', {});
const plansDoc = read('plans.json', { plans: [] });
const checks = read('checks.json', {});
const teamDoc = read('web/team.json', null);
const boardDoc = read('board.json', null);
let events = [];
try {
  events = fs.readFileSync(path.join(dir, 'crm.log'), 'utf8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
} catch { /* no history yet */ }

const sqlTs = (iso) => (iso ? new Date(iso).toISOString().replace('T', ' ').replace('Z', '') : null);
const day = (v) => (/^\d{4}-\d{2}-\d{2}$/.test(String(v || '')) ? v : null);
const s = (v) => (v === null || v === undefined ? '' : String(v));
const num = (v) => (s(v).trim() === '' || Number.isNaN(Number(s(v).replace(/[$,]/g, ''))) ? null : Number(s(v).replace(/[$,]/g, '')));

const TEXT = ['col', 'sub', 'dead', 'contact', 'role', 'phone', 'email', 'next_action', 'qr_where', 'device_given', 'incentive_note',
  'name', 'address', 'city', 'metro', 'kind', 'via', 'photo', 'rating', 'reviews', 'g_type', 'hours', 'verified', 'confirm',
  'plan_id', 'last_note', 'removed_by'];

const OLD = { todo: ['planned', ''], visited: ['visited', 'l1'], met: ['visited', 'l3'], interested: ['visited', 'l5'], signed: ['sales', ''], revisit: ['visited', ''], no: ['visited', ''], closed: ['visited', ''], moved: ['visited', ''] };

(async () => {
  const conn = await mysql.createConnection({ host: process.env.DB_HOST, user: process.env.DB_USER, password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME, port: process.env.DB_PORT || 3306 });
  const [[{ n }]] = await conn.query('SELECT COUNT(*) AS n FROM fc_cards');
  if (n && !replace) { console.error(`fc_cards already has ${n} cards. Re-run with --replace to empty the fc_* tables first.`); process.exit(1); }
  await conn.beginTransaction();
  try {
    if (replace) for (const t of ['fc_plan_stops', 'fc_day_plans', 'fc_place_checks', 'fc_events', 'fc_cards', 'fc_board', 'fc_reps', 'fc_markets']) await conn.query(`DELETE FROM ${t}`);

    if (teamDoc) {
      for (const [i, m] of teamDoc.markets.entries()) {
        await conn.query('INSERT INTO fc_markets (`key`, name, metros, tz, tz_label, cc, position) VALUES (?, ?, ?, ?, ?, ?, ?)',
          [m.key, m.name, JSON.stringify(m.metros || []), m.tz || 'America/Chicago', m.tz_label || '', m.cc || '1', i]);
      }
      for (const [i, r] of teamDoc.reps.entries()) {
        await conn.query(`INSERT INTO fc_reps (\`key\`, user_id, name, role, market_key, phone, base_lat, base_lon, base_label, position)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [r.key, links[r.key] || null, r.name, r.role === 'manager' ? 'manager' : 'rep', r.market || null, r.phone || '',
          r.base ? r.base.lat : null, r.base ? r.base.lon : null, r.base ? r.base.label || '' : '', i]);
      }
    }
    if (boardDoc && boardDoc.columns) await conn.query('INSERT INTO fc_board (id, `columns`) VALUES (1, ?)', [JSON.stringify(boardDoc.columns)]);

    for (const [pid, c] of Object.entries(cards)) {
      if (!c.col && c.status) { const m = OLD[c.status] || ['planned', '']; c.col = m[0]; c.sub = c.sub || m[1]; }
      const row = { place_id: pid, rep_key: s(c.rep), next_date: day(c.next_date), plan_date: day(c.plan_date),
        plan_stop: parseInt(c.plan_stop, 10) || null, incentive: num(c.incentive), lat: num(c.lat), lon: num(c.lon),
        removed: c.removed ? 1 : 0, removed_reason: c.removed ? s(c.removed_reason) : null, removed_at: c.removed ? sqlTs(c.removed_at) : null,
        col_since: sqlTs(c.col_since || c.updated || c.created), first_visit: day(c.first_visit), last_visit: day(c.last_visit),
        touches: +c.touches || 0, notes_n: +c.notes_n || 0, last_note_at: sqlTs(c.last_note_at),
        created_at: sqlTs(c.created) || sqlTs(new Date().toISOString()), updated_at: sqlTs(c.updated) || sqlTs(new Date().toISOString()) };
      for (const k of TEXT) row[k] = s(c[k]);
      if (!['', 'closed', 'moved'].includes(row.dead)) row.dead = '';
      if (!['', 'yes', 'no'].includes(row.device_given)) row.device_given = '';
      row.last_note = row.last_note.slice(0, 280);
      const cols = Object.keys(row);
      await conn.query(`INSERT INTO fc_cards (${cols.map((x) => '`' + x + '`').join(',')}) VALUES (${cols.map(() => '?').join(',')})`, cols.map((x) => row[x]));
    }

    const known = ['type', 'place_id', 'rep', 'at', 'on', 'col', 'sub', 'from', 'from_sub', 'text', 'reason', 'changes'];
    for (const e of events) {
      if (!e.place_id || !e.at) continue;
      let type = e.type;
      if (!type) type = !e.from ? 'added' : e.from !== e.col ? 'move' : 'edit';   // lines from before events were typed
      const extra = {};
      for (const [k, v] of Object.entries(e)) if (!known.includes(k) && v !== undefined) extra[k] = v;
      await conn.query(`INSERT INTO fc_events (place_id, type, rep_key, at, on_day, col, sub, from_col, from_sub, text, reason, changes, extra)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [e.place_id, type, s(e.rep), sqlTs(e.at), day(e.on) || sqlTs(e.at).slice(0, 10), e.col ?? null, e.sub ?? null, e.from ?? null,
        e.from_sub ?? null, e.text ?? null, e.reason ?? null, e.changes ? JSON.stringify(e.changes) : null,
        Object.keys(extra).length ? JSON.stringify(extra) : null]);
    }

    for (const p of plansDoc.plans || []) {
      if (!p.rep || !day(p.date) || !(p.stops || []).length) continue;
      const id = `${p.rep}:${p.date}`;
      await conn.query('INSERT INTO fc_day_plans (id, rep_key, plan_date, name, created_at) VALUES (?, ?, ?, ?, ?)',
        [id, p.rep, p.date, s(p.name).slice(0, 120), sqlTs(p.created) || sqlTs(new Date().toISOString())]);
      for (const [i, st] of p.stops.entries()) await conn.query('INSERT INTO fc_plan_stops (plan_id, position, place_id) VALUES (?, ?, ?)', [id, i + 1, st]);
    }

    for (const [pid, c] of Object.entries(checks)) {
      await conn.query('INSERT INTO fc_place_checks (place_id, status, name, checked_at, checked_on, was, changed_on) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [pid, c.status || 'UNKNOWN', s(c.name).slice(0, 200), sqlTs(c.at), day(c.on) || sqlTs(c.at).slice(0, 10), c.was || null, day(c.changed_on)]);
    }

    const counts = {};
    for (const t of ['fc_markets', 'fc_reps', 'fc_cards', 'fc_events', 'fc_day_plans', 'fc_plan_stops', 'fc_place_checks']) {
      const [[r]] = await conn.query(`SELECT COUNT(*) AS n FROM ${t}`); counts[t] = r.n;
    }
    console.log('Read:', { cards: Object.keys(cards).length, events: events.length, plans: (plansDoc.plans || []).length, checks: Object.keys(checks).length });
    console.log('In the database:', counts);
    if (dry) { await conn.rollback(); console.log('Dry run: rolled back, nothing written.'); }
    else { await conn.commit(); console.log('Committed.'); }
  } catch (e) {
    await conn.rollback();
    console.error('Import failed, nothing written:', e.message);
    process.exitCode = 1;
  } finally {
    await conn.end();
  }
})();
