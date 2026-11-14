// Foundry API: sign-in, invitations, and the shared platform data.
// Runs as a Netlify Function (v2). Storage is Netlify Blobs.
import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

export const config = { path: '/api/*' };

const ENV = (k) => {
  if (globalThis.__FDY_ENV && globalThis.__FDY_ENV[k] !== undefined) return globalThis.__FDY_ENV[k];
  try { const v = globalThis.Netlify && globalThis.Netlify.env && globalThis.Netlify.env.get(k); if (v !== undefined && v !== null && v !== '') return v; } catch {}
  return process.env[k];
};
// Imported .env values can carry stray spaces, line endings or quotes. Clean them.
const ENVC = (k) => { const v = ENV(k); return typeof v === 'string' ? v.replace(/^\s*(["'])(.*)\1\s*$/, '$2').trim() : v; };
const store = () => globalThis.__FDY_STORE || getStore({ name: 'foundry', consistency: 'strong' });

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });
const fail = (status, error) => json({ error }, status);

const today = () => new Date().toISOString().slice(0, 10);
const addDays = (d, n) => { const x = new Date(d + 'T00:00:00Z'); x.setUTCDate(x.getUTCDate() + n); return x.toISOString().slice(0, 10); };
const lc = (s) => String(s || '').trim().toLowerCase();
const EMAIL_RE = /^[^@\s]+@[^@\s]+\.[^@\s]+$/;
const ROLES = ['Admin', 'Super admin', 'Panelist', 'Sponsor user', 'Creator'];

/* ---------- storage helpers ---------- */
async function getJ(key, fallback) { const v = await store().get(key, { type: 'json' }); return v ?? fallback; }
async function setJ(key, val) { await store().setJSON(key, val); }

/* ---------- passwords and sessions ---------- */
function hashPw(pw, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(String(pw), salt, 64).toString('hex') };
}
function checkPw(pw, rec) {
  if (!rec) return false;
  const h = crypto.scryptSync(String(pw), rec.salt, 64);
  const b = Buffer.from(rec.hash, 'hex');
  return b.length === h.length && crypto.timingSafeEqual(b, h);
}
const secret = () => ENVC('SESSION_SECRET');
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
  return body + '.' + sig;
}
function verify(token) {
  try {
    const [body, sig] = String(token).split('.');
    const good = crypto.createHmac('sha256', secret()).update(body).digest('base64url');
    if (!sig || sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
    const p = JSON.parse(Buffer.from(body, 'base64url').toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}

/* ---------- shared state ---------- */
async function loadDoc() {
  return (await getJ('state', null)) || { version: 0, state: { users: [] } };
}
async function saveDoc(doc) { doc.version += 1; await setJ('state', doc); return doc; }

function linkFor(state, user) {
  const e = lc(user.email);
  if (user.role === 'Panelist') { const p = (state.panelists || []).find((x) => lc(x.email) === e); return { role: 'panelist', uid: p && p.id }; }
  if (user.role === 'Sponsor user') return { role: 'sponsor', uid: user.org };
  if (user.role === 'Creator') { const c = (state.creators || []).find((x) => lc(x.email) === e); return { role: 'creator', uid: c && c.id }; }
  return { role: 'admin', uid: user.id };
}
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role });

async function authed(req) {
  if (!secret()) return { err: fail(500, 'SESSION_SECRET is not set on the server.') };
  const h = req.headers.get('authorization') || '';
  const p = verify(h.replace(/^Bearer\s+/i, ''));
  if (!p) return { err: fail(401, 'Please sign in again.') };
  const doc = await loadDoc();
  const u = (doc.state.users || []).find((x) => x.id === p.uid);
  if (!u || u.state !== 'Active') return { err: fail(401, 'This account is no longer active.') };
  return { doc, user: u };
}
const adminOnly = (a) => (a.user.role === 'Admin' || a.user.role === 'Super admin') ? null : fail(403, 'Admins only.');

function startSession(doc, user) {
  const token = sign({ uid: user.id, exp: Date.now() + 1000 * 60 * 60 * 24 * 14 });
  return { token, user: publicUser(user), link: linkFor(doc.state, user) };
}

/* ---------- email ---------- */
async function sendInviteEmail(user, link, inviter) {
  const key = ENVC('RESEND_API_KEY'), from = ENVC('FROM_EMAIL');
  if (!key || !from) return { sent: false, reason: 'Email is not configured (set RESEND_API_KEY and FROM_EMAIL).' };
  const first = String(user.name).split(' ')[0];
  const article = /^[aeiou]/i.test(user.role) ? 'an' : 'a';
  const text = `Hello ${first},\n\n${inviter} has invited you to join The Foundry as ${article} ${user.role}.\n\nOpen your personal link, choose a password and sign in:\n${link}\n\nThe link works once and expires on ${user.expires}. If you were not expecting this, ignore this email.\n\nThe Foundry team`;
  const html = `<div style="font-family:Arial,sans-serif;max-width:520px;margin:auto;color:#17202E"><h2 style="color:#0F2557">You are invited to The Foundry</h2><p>Hello ${esc(first)},</p><p>${esc(inviter)} has invited you to join The Foundry as ${article} <b>${esc(user.role)}</b>.</p><p><a href="${link}" style="display:inline-block;background:#0F2557;color:#fff;padding:12px 22px;border-radius:999px;text-decoration:none;font-weight:700">Accept invitation</a></p><p style="font-size:13px;color:#5B6678">Or paste this link into your browser:<br>${link}</p><p style="font-size:13px;color:#5B6678">The link works once and expires on ${esc(user.expires)}. If you were not expecting this, ignore this email.</p></div>`;
  try {
    const r = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { authorization: 'Bearer ' + key, 'content-type': 'application/json' },
      body: JSON.stringify({ from, to: [user.email], subject: `You are invited to The Foundry as ${article} ${user.role}`, text, html }),
    });
    if (!r.ok) return { sent: false, reason: 'Email provider said: ' + (await r.text()).slice(0, 200) };
    return { sent: true };
  } catch (e) { return { sent: false, reason: 'Could not reach the email provider.' }; }
}
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const siteUrl = (req) => (ENVC('SITE_URL') || new URL(req.url).origin).replace(/\/$/, '');

/* ---------- invitations ---------- */
async function createInvite(req, a, input) {
  const { doc } = a;
  const st = doc.state;
  const name = String(input.name || '').trim(), email = lc(input.email), role = input.role;
  if (!name) return fail(400, 'Enter a name.');
  if (!EMAIL_RE.test(email)) return fail(400, 'Enter a valid email address.');
  if (!ROLES.includes(role)) return fail(400, 'Choose a role.');
  if (/admin/i.test(role) && a.user.role !== 'Super admin') return fail(403, 'Only a Super admin can invite admins.');
  if ((st.users || []).some((u) => lc(u.email) === email && !['Revoked', 'Cancelled'].includes(u.state))) return fail(409, 'That email already has an account or a pending invitation.');
  const user = { id: 'u' + crypto.randomBytes(4).toString('hex'), name, email, role, state: 'Invited', invited: today(), expires: addDays(today(), Math.min(30, Math.max(1, +input.days || 7))) };
  if (role === 'Sponsor user') {
    st.orgs = st.orgs || [];
    if (input.org && input.org !== '__new' && st.orgs.find((o) => o.id === input.org)) user.org = input.org;
    else {
      const nm = String(input.orgname || '').trim();
      if (!nm) return fail(400, 'Choose an organisation or type a new name.');
      const id = 's' + (st.orgs.length + 1) + crypto.randomBytes(2).toString('hex');
      st.orgs.push({ id, name: nm, group: ['g1', 'g2', 'g3'].includes(input.group) ? input.group : 'g1', role: String(input.orgrole || ''), expertise: [], linked: [], user: name, email, accepted: false });
      user.org = id;
    }
  }
  st.users = st.users || [];
  st.users.push(user);
  return finishInvite(req, a, doc, user);
}
async function finishInvite(req, a, doc, user, send = true) {
  const invites = await getJ('invites', {});
  for (const [t, v] of Object.entries(invites)) if (v.uid === user.id) delete invites[t];
  const token = crypto.randomBytes(24).toString('hex');
  invites[token] = { uid: user.id, exp: user.expires };
  await setJ('invites', invites);
  await saveDoc(doc);
  const link = siteUrl(req) + '/#accept?t=' + token;
  const mail = send ? await sendInviteEmail(user, link, a.user.name || 'The Foundry team') : { sent: false, reason: '' };
  return json({ user, link, emailed: mail.sent, emailNote: mail.reason || '' });
}

/* ---------- routes ---------- */
export default async (req) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/api\/?/, '').replace(/\/$/, '');
  const method = req.method;
  let body = {};
  if (method === 'POST' || method === 'PUT') { try { body = await req.json(); } catch { body = {}; } }

  try {
    if (path === 'health') {
      return json({ ok: true, configured: !!secret(), mail: !!(ENVC('RESEND_API_KEY') && ENVC('FROM_EMAIL')), bootstrap: !!(ENVC('ADMIN_EMAIL') && ENVC('ADMIN_PASSWORD')), firstRun: !Object.keys(await getJ('creds', {})).length });
    }
    if (!secret()) return fail(500, 'SESSION_SECRET is not set on the server.');

    /* sign in */
    if (path === 'login' && method === 'POST') {
      const email = lc(body.email), pw = String(body.pw || '');
      let creds = await getJ('creds', {});
      const doc = await loadDoc();
      // First run: create the Super admin from environment variables.
      if (!Object.keys(creds).length && ENVC('ADMIN_EMAIL') && email === lc(ENVC('ADMIN_EMAIL')) && pw.trim() === ENVC('ADMIN_PASSWORD')) {
        const u = { id: 'u1', name: ENVC('ADMIN_NAME') || 'Programme admin', email, role: 'Super admin', state: 'Active', joined: today() };
        doc.state.users = [u];
        creds[email] = hashPw(pw.trim());
        await setJ('creds', creds);
        await saveDoc(doc);
        return json(startSession(doc, u));
      }
      // Before the first account exists, say which part of the sign-in did not match, so setup mistakes are easy to fix.
      if (!Object.keys(creds).length && ENVC('ADMIN_EMAIL') && ENVC('ADMIN_PASSWORD')) {
        if (email !== lc(ENVC('ADMIN_EMAIL'))) return fail(401, 'Setup check: this email does not match the ADMIN_EMAIL setting on the server. Check it in Netlify and sign in with exactly that address.');
        return fail(401, 'Setup check: the email matches, but the password does not match the ADMIN_PASSWORD setting. Re-enter ADMIN_PASSWORD in Netlify, redeploy and try again.');
      }
      const rec = creds[email];
      const u = (doc.state.users || []).find((x) => lc(x.email) === email);
      if (!rec || !u || !checkPw(pw, rec)) return fail(401, 'Incorrect email or password. Check your details and try again.');
      if (u.state !== 'Active') return fail(403, u.state === 'Revoked' ? 'This account has been revoked. Contact the Foundry team.' : 'This account is not active.');
      return json(startSession(doc, u));
    }

    /* creator self-registration (public) */
    if (path === 'register' && method === 'POST') {
      const name = String(body.name || '').trim(), email = lc(body.email), pw = String(body.pw || '');
      if (!name) return fail(400, 'Enter your name.');
      if (!EMAIL_RE.test(email)) return fail(400, 'Enter a valid email address.');
      if (pw.length < 8) return fail(400, 'Use at least 8 characters.');
      const doc = await loadDoc(), st = doc.state;
      if ((st.users || []).some((u) => lc(u.email) === email && !['Revoked', 'Cancelled'].includes(u.state))) return fail(409, 'That email already has an account. Sign in instead.');
      const creds = await getJ('creds', {});
      const u = { id: 'u' + crypto.randomBytes(4).toString('hex'), name, email, role: 'Creator', state: 'Active', joined: today() };
      st.users = (st.users || []).filter((x) => lc(x.email) !== email).concat(u);
      st.creators = st.creators || [];
      if (!st.creators.find((c) => lc(c.email) === email)) st.creators.push({ id: 'c' + (st.creators.length + 1) + crypto.randomBytes(2).toString('hex'), name, email, city: '', phone: '', skills: '', org: '', heard: '', done: false });
      creds[email] = hashPw(pw);
      await setJ('creds', creds);
      await saveDoc(doc);
      return json(startSession(doc, u));
    }

    /* invitation details for the accept page (public) */
    if (path === 'invite' && method === 'GET') {
      const invites = await getJ('invites', {});
      const inv = invites[url.searchParams.get('t') || ''];
      const doc = await loadDoc();
      const u = inv && (doc.state.users || []).find((x) => x.id === inv.uid);
      if (!u) return fail(404, 'This invitation link is not valid. Ask the Foundry team to send you a new one.');
      if (u.state === 'Cancelled') return fail(410, 'This invitation was cancelled. Ask the Foundry team for a new one.');
      if (u.state === 'Revoked') return fail(410, 'This account has been revoked.');
      if (u.state === 'Active') return fail(410, 'This invitation has already been used. Sign in with the password you chose.');
      if (today() > u.expires) return fail(410, 'This invitation expired on ' + u.expires + '. Ask the Foundry team to renew it.');
      const org = u.org ? (doc.state.orgs || []).find((o) => o.id === u.org) : null;
      return json({ name: u.name, email: u.email, role: u.role, org: org ? org.name : '' });
    }

    /* accept (public, single use) */
    if (path === 'accept' && method === 'POST') {
      const pw = String(body.pw || '');
      if (pw.length < 8) return fail(400, 'Use at least 8 characters.');
      const invites = await getJ('invites', {});
      const inv = invites[String(body.t || '')];
      const doc = await loadDoc();
      const st = doc.state;
      const u = inv && (st.users || []).find((x) => x.id === inv.uid);
      if (!u || u.state !== 'Invited') return fail(410, 'This invitation is no longer valid.');
      if (today() > u.expires) return fail(410, 'This invitation has expired.');
      u.name = String(body.name || '').trim() || u.name;
      u.state = 'Active'; u.joined = today(); delete u.expires;
      const e = lc(u.email);
      if (u.role === 'Panelist') { st.panelists = st.panelists || []; if (!st.panelists.find((p) => lc(p.email) === e)) st.panelists.push({ id: 'p' + (st.panelists.length + 1) + crypto.randomBytes(2).toString('hex'), name: u.name, email: u.email, active: true }); }
      if (u.role === 'Sponsor user') { const o = (st.orgs || []).find((x) => x.id === u.org); if (o) { o.user = o.user || u.name; o.accepted = true; } }
      if (u.role === 'Creator') { st.creators = st.creators || []; if (!st.creators.find((c) => lc(c.email) === e)) st.creators.push({ id: 'c' + (st.creators.length + 1) + crypto.randomBytes(2).toString('hex'), name: u.name, email: u.email, city: '', phone: '', skills: '', org: '', heard: '', done: false }); }
      const creds = await getJ('creds', {});
      creds[e] = hashPw(pw);
      await setJ('creds', creds);
      delete invites[body.t];
      await setJ('invites', invites);
      await saveDoc(doc);
      return json(startSession(doc, u));
    }

    /* everything below needs a signed-in user */
    const a = await authed(req);
    if (a.err) return a.err;

    if (path === 'state' && method === 'GET') return json({ version: a.doc.version, state: a.doc.state });

    if (path === 'state' && method === 'PUT') {
      const cur = a.doc;
      if (+body.base !== cur.version) return json({ error: 'conflict', version: cur.version, state: cur.state }, 409);
      const next = body.state && typeof body.state === 'object' ? body.state : null;
      if (!next) return fail(400, 'No state.');
      next.users = cur.state.users;   // accounts are changed only through the user endpoints
      delete next.session; delete next.ui;
      cur.state = next;
      await saveDoc(cur);
      return json({ version: cur.version });
    }

    const denied = adminOnly(a);
    if (path.startsWith('invite') || path.startsWith('user')) { if (denied) return denied; }

    if (path === 'invite' && method === 'POST') return createInvite(req, a, body);

    const target = () => (a.doc.state.users || []).find((u) => u.id === body.id);
    if (path === 'invite/resend' && method === 'POST') {
      const u = target(); if (!u) return fail(404, 'Not found.');
      if (/admin/i.test(u.role) && a.user.role !== 'Super admin') return fail(403, 'Only a Super admin can invite admins.');
      if (u.state === 'Active') return fail(409, 'Already active.');
      u.state = 'Invited'; u.expires = addDays(today(), 7);
      return finishInvite(req, a, a.doc, u);
    }
    if (path === 'invite/cancel' && method === 'POST') {
      const u = target(); if (!u) return fail(404, 'Not found.');
      if (u.state === 'Active') return fail(409, 'Already active.');
      u.state = 'Cancelled';
      const invites = await getJ('invites', {});
      for (const [t, v] of Object.entries(invites)) if (v.uid === u.id) delete invites[t];
      await setJ('invites', invites);
      await saveDoc(a.doc);
      return json({ ok: true });
    }
    if (path === 'user/revoke' && method === 'POST') {
      const u = target(); if (!u) return fail(404, 'Not found.');
      if (/admin/i.test(u.role)) {
        if (a.user.role !== 'Super admin') return fail(403, 'Only a Super admin can revoke admins.');
        if (a.doc.state.users.filter((x) => /admin/i.test(x.role) && x.state === 'Active').length <= 1) return fail(409, 'Keep at least one active admin.');
      }
      if (u.id === a.user.id) return fail(409, 'You cannot revoke your own access.');
      u.state = 'Revoked';
      const p = (a.doc.state.panelists || []).find((x) => lc(x.email) === lc(u.email)); if (p) p.active = false;
      await saveDoc(a.doc);
      return json({ ok: true });
    }
    if (path === 'user/restore' && method === 'POST') {
      const u = target(); if (!u) return fail(404, 'Not found.');
      u.state = 'Active';
      const p = (a.doc.state.panelists || []).find((x) => lc(x.email) === lc(u.email)); if (p) p.active = true;
      await saveDoc(a.doc);
      return json({ ok: true });
    }
    if (path === 'invite/link' && method === 'POST') {
      const u = target(); if (!u || u.state !== 'Invited') return fail(404, 'Not found.');
      return finishInvite(req, a, a.doc, u, false);
    }
    return fail(404, 'Not found.');
  } catch (e) {
    console.error(e);
    return fail(500, 'Server error. Check the function logs.');
  }
};
