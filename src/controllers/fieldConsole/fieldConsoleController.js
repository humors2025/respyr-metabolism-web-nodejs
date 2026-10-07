'use strict';

/*
|--------------------------------------------------------------------------
| Field Console API — /dietitian/api/web/field/*
|--------------------------------------------------------------------------
| What salesforce.rysflo.com calls. Same paths and JSON as the console's
| local server (Field Console/serve.py) had under /api/*, so the console only
| changes its base URL.
|
| Who may call it: super_admin (Rysflo India — the manager view) and admin
| (the US trainer admins, Derek and Evan). Each caller is matched to an
| fc_reps row by their login (fc_reps.user_id = token user_id). A rep's saves
| are always filed under their own rep key, whatever the request says; a
| manager may act for a named rep (planning a day for Derek, say).
*/

const axios = require('axios');
const fc = require('../../services/fieldConsole');

const ALLOWED_ROLES = ['super_admin', 'admin'];
const PLACES = 'https://places.googleapis.com/v1';
const mapsKey = () => process.env.GOOGLE_MAPS_KEY || process.env.GOOGLE_MAPS_API_KEY || '';

/* The caller: their role, and their rep row if they have one. */
async function actorOf(req) {
  const role = String(req.user?.role || req.user?.dietician?.role || '').trim().toLowerCase();
  const userId = String(req.user?.user_id || '').trim().toLowerCase();
  if (!ALLOWED_ROLES.includes(role)) return { allowed: false };
  const t = await fc.team();
  const rep = t.reps.find((r) => r.user_id && r.user_id === userId) || null;
  const manager = role === 'super_admin' || (rep && rep.role === 'manager');
  return { allowed: true, role, userId, rep, manager, team: t };
}

/* The rep key a write is filed under. */
function repFor(actor, asked) {
  if (actor.manager) return String(asked || (actor.rep && actor.rep.key) || '').slice(0, 32);
  return actor.rep.key;
}

/* Wrap a handler: auth, the actor, and errors the console can show. */
const handle = (fn, { write = false, managerOnly = false } = {}) => async (req, res) => {
  try {
    const actor = await actorOf(req);
    if (!actor.allowed) return res.status(403).json({ error: 'The field console is for the field team.' });
    if (write && !actor.manager && !actor.rep) {
      return res.status(403).json({ error: 'Your login is not set up as a rep yet. Ask for it to be linked on the Team page.' });
    }
    if (managerOnly && !actor.manager) return res.status(403).json({ error: 'Only a manager can change this.' });
    const out = await fn(req, actor, res);
    if (out !== undefined) res.json(out);
  } catch (e) {
    if (e instanceof fc.FieldError) return res.status(400).json({ error: e.message });
    console.error('FIELD_CONSOLE_ERROR:', { path: req.path, message: e?.message, code: e?.code });
    return res.status(500).json({ error: 'The server could not save that. Try again in a minute.' });
  }
};

const body = (req) => (req.body && typeof req.body === 'object' ? req.body : {});

/* ---------------------------------------------------------------- reads */

const me = handle(async (req, actor) => ({
  user_id: actor.userId, role: actor.role, manager: actor.manager,
  rep: actor.rep ? actor.rep.key : null, team: actor.team,
}));

const crm = handle(async () => ({
  records: await fc.allRecords(), board: await fc.board(), plans: await fc.plans(), summary: await fc.summary(),
}));

const history = handle(async (req) => ({ history: await fc.history(req.query.place_id || '') }));

const log = handle(async (req) => ({ log: await fc.log(req.query.limit, req.query.rep || null) }));

const exportCsv = handle(async (req, actor, res) => {
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="field-crm.csv"');
  res.send(await fc.exportCsv());
});

const team = handle(async () => ({ team: await fc.team() }));

const checks = handle(async () => ({ checks: await fc.checks() }));

/* ---------------------------------------------------------------- writes */

const save = handle(async (req, actor) => {
  const p = body(req);
  const rec = await fc.save(p.place_id, { ...p, rep: repFor(actor, p.rep) });
  return { record: rec, summary: await fc.summary() };
}, { write: true });

const note = handle(async (req, actor) => {
  const p = body(req);
  const rec = await fc.addNote(p.place_id, p.text, repFor(actor, p.rep), p.on || null);
  return { record: rec, summary: await fc.summary() };
}, { write: true });

const remove = handle(async (req, actor) => {
  const p = body(req);
  const rec = await fc.setRemoved(p.place_id, !p.restore, p.reason || '', repFor(actor, p.rep));
  return { record: rec, summary: await fc.summary() };
}, { write: true });

const plan = handle(async (req, actor) => {
  const p = body(req);
  const res = await fc.planDay({ ...p, rep: repFor(actor, p.rep) });
  return { ...res, plans: await fc.plans(), records: await fc.allRecords(), summary: await fc.summary() };
}, { write: true });

const planMove = handle(async (req, actor) => {
  const p = body(req);
  const rec = await fc.moveToDay(p.place_id, p.date, repFor(actor, p.rep), p.at);
  return { record: rec, records: await fc.allRecords(), plans: await fc.plans(), summary: await fc.summary() };
}, { write: true });

const planDelete = handle(async (req) => {
  await fc.deletePlan(body(req).id || '');
  return { plans: await fc.plans() };
}, { write: true, managerOnly: true });

const saveBoard = handle(async (req) => ({ board: await fc.saveBoard(body(req)) }), { write: true, managerOnly: true });

const saveTeam = handle(async (req) => ({ team: await fc.saveTeam(body(req)) }), { write: true, managerOnly: true });

/* ---------------------------------------------------------------- Google */

const searchFields = 'places.id,places.displayName,places.formattedAddress,places.location,places.businessStatus,'
  + 'places.primaryTypeDisplayName,places.addressComponents,places.rating,places.userRatingCount,places.photos,'
  + 'places.nationalPhoneNumber,places.regularOpeningHours';

function placeOut(p) {
  const city = (p.addressComponents || []).find((c) => (c.types || []).includes('locality'))?.longText || '';
  const type = (p.primaryTypeDisplayName || {}).text || '';
  return {
    place_id: p.id, name: p.displayName?.text || '', address: p.formattedAddress || '', city,
    lat: p.location?.latitude, lon: p.location?.longitude, kind: type, status: p.businessStatus || '',
    g_type: type, rating: p.rating ?? '', reviews: p.userRatingCount ?? '',
    photo: ((p.photos || [{}])[0] || {}).name || '', phone: p.nationalPhoneNumber || '',
    hours: ((p.regularOpeningHours || {}).weekdayDescriptions || []).join(' / '), verified: p.businessStatus || '',
  };
}

async function searchText(body) {
  const r = await axios.post(`${PLACES}/places:searchText`, body, {
    headers: { 'X-Goog-Api-Key': mapsKey(), 'X-Goog-FieldMask': searchFields }, timeout: 10000,
  });
  return r.data.places || [];
}

const places = handle(async (req, actor, res) => {
  const term = String(req.query.q || '').trim();
  if (term.length < 3) return { places: [] };
  try {
    const raw = await searchText({ textQuery: term, maxResultCount: 6,
      locationBias: { rectangle: { low: { latitude: 25.8, longitude: -115.0 }, high: { latitude: 37.0, longitude: -93.5 } } } });
    return { places: raw.map(placeOut) };
  } catch (e) {
    res.status(502).json({ error: 'Google search failed' });
    return undefined;
  }
});

/* A Google Maps link (often a short maps.app.goo.gl one) turned into a place. */
const resolve = handle(async (req, actor, res) => {
  const url = String(req.query.url || '').trim();
  if (!/^https?:\/\//.test(url)) { res.status(400).json({ error: 'Paste the whole link, starting with https://' }); return undefined; }
  let final = url;
  let reached = false;
  // A short link's redirect already holds the place's name and pin: read the
  // Location header and stop. Following it downloads the whole Maps page
  // (~12 s), which timed out. Up to 5 hops, 3 tries.
  for (let attempt = 0; attempt < 3 && !reached; attempt += 1) {
    try {
      let cur = url;
      for (let hop = 0; hop < 5; hop += 1) {
        if (cur !== url && /google\.[a-z.]+\/maps|[?&](q|ll|query)=/.test(cur)) break;
        const r = await axios.head(cur, { maxRedirects: 0, timeout: 8000, headers: { 'User-Agent': 'Mozilla/5.0' }, validateStatus: () => true });
        const nxt = r.headers && r.headers.location;
        if (!nxt) break;
        cur = new URL(nxt, cur).toString();
      }
      final = cur;
      reached = true;
    } catch { await new Promise((ok) => setTimeout(ok, 600 * (attempt + 1))); }
  }
  const dec = decodeURIComponent(final);
  let lat = null, lon = null;
  for (const pat of [/!3d(-?\d+\.\d+)!4d(-?\d+\.\d+)/, /@(-?\d+\.\d+),(-?\d+\.\d+)/, /[?&](?:q|ll|query)=(-?\d+\.\d+),\s*(-?\d+\.\d+)/]) {
    const m = dec.match(pat);
    if (m) { lat = +m[1]; lon = +m[2]; break; }
  }
  const nm = dec.match(/\/place\/([^/@?]+)/);
  const name = nm ? nm[1].replace(/\+/g, ' ').trim() : '';
  const out = { url: final, name, lat, lon, google: null, unreached: !reached && !name && lat === null };
  if (name || lat !== null) {
    const q = { textQuery: name || `${lat},${lon}`, maxResultCount: 3 };
    if (lat !== null) q.locationBias = { circle: { center: { latitude: lat, longitude: lon }, radius: 400 } };
    let hits = [];
    try { hits = await searchText(q); } catch { hits = []; }
    const km = (a, b) => { const r = (x) => (x * Math.PI) / 180; return 6371 * 2 * Math.asin(Math.sqrt(Math.sin(r(b[0] - a[0]) / 2) ** 2 + Math.cos(r(a[0])) * Math.cos(r(b[0])) * Math.sin(r(b[1] - a[1]) / 2) ** 2)); };
    for (const h of hits) {
      const hl = [h.location.latitude, h.location.longitude];
      if (lat !== null && km([lat, lon], hl) > 0.3) continue;   // same name across town is a different business
      out.google = placeOut(h);
      break;
    }
  }
  return out;
});

/* Is it still there? Google's business status for each place, at most weekly. */
const check = handle(async (req) => {
  const p = body(req);
  const ids = (p.place_ids || []).map(String).filter((i) => i && !i.startsWith('manual:')).slice(0, 60);
  const todo = await fc.staleChecks(ids, Boolean(p.force));
  const found = {};
  let failed = 0;
  const one = async (pid) => {
    try {
      const r = await axios.get(`${PLACES}/places/${encodeURIComponent(pid)}`, {
        headers: { 'X-Goog-Api-Key': mapsKey(), 'X-Goog-FieldMask': 'id,businessStatus,displayName' }, timeout: 10000,
      });
      found[pid] = { status: r.data.businessStatus || 'OPERATIONAL', name: r.data.displayName?.text || '' };
    } catch (e) {
      if (e.response && e.response.status === 404) found[pid] = { status: 'NOT_FOUND' };
      else failed += 1;
    }
  };
  for (let i = 0; i < todo.length; i += 8) await Promise.all(todo.slice(i, i + 8).map(one));
  if (Object.keys(found).length) await fc.saveChecks(found);
  return { checks: await fc.checks(ids), asked: todo.length, cached: ids.length - todo.length, failed };
}, { write: true });

/* The day's stops in the fastest driving order (Google Routes API): start
   where the rep says, end at their base. stops: [{id, lat, lon}], up to 25. */
const order = handle(async (req, actor, res) => {
  const b = req.body || {};
  const pts = (Array.isArray(b.stops) ? b.stops : []).filter((x) => x && x.lat !== null && x.lat !== undefined).slice(0, 25);
  const start = b.start || {}, end = b.end || b.start || {};
  if (pts.length < 2 || start.lat === null || start.lat === undefined) return { order: pts.map((p) => p.id) };
  const ll = (p) => ({ location: { latLng: { latitude: +p.lat, longitude: +p.lon } } });
  try {
    const r = await axios.post('https://routes.googleapis.com/directions/v2:computeRoutes',
      { origin: ll(start), destination: ll(end), intermediates: pts.map(ll), travelMode: 'DRIVE', optimizeWaypointOrder: true },
      { headers: { 'X-Goog-Api-Key': mapsKey(), 'X-Goog-FieldMask': 'routes.optimizedIntermediateWaypointIndex,routes.distanceMeters,routes.duration' }, timeout: 20000 });
    const route = (r.data.routes || [{}])[0];
    const idx = route.optimizedIntermediateWaypointIndex || pts.map((_, i) => i);
    return { order: idx.map((i) => pts[i].id), km: Math.round((route.distanceMeters || 0) / 100) / 10,
      minutes: Math.round(parseInt(String(route.duration || '0s'), 10) / 60) };
  } catch (e) {
    res.status(502).json({ error: 'Google could not work out the order' });
    return undefined;
  }
});

module.exports = {
  me, crm, history, log, exportCsv, team, checks,
  save, note, remove, plan, planMove, planDelete, saveBoard, saveTeam,
  places, resolve, check, order,
};
