"use strict";
/**
 * Local development seed for the gym-referral work.
 *
 * Creates the full hierarchy so every dashboard has data:
 *
 *   connect@respyr.in         super_admin   RESPYRD01
 *   └─ evan@test.local        admin (TA)    RESPYRD05
 *      └─ Iron Works Gym      facility      TRX1234
 *         owner@ironworks.test facility_admin TRX1234  (facility partner code == owner code)
 *         ├─ tanner@ironworks.test trainer  TRN0000001  split 50%
 *         │    clients: c1, c2, self (tanner as his own client)
 *         └─ sophia@ironworks.test trainer  TRN0000002  split 0%
 *              clients: c3
 *
 * Password for every account: Passw0rd!Test
 *
 * SAFETY: refuses to run unless DB_HOST is loopback. Never point this at UAT.
 * Idempotent: deletes and recreates only the seed emails / codes listed here.
 */
require("dotenv").config();
const bcrypt = require("bcrypt");
const pool = require("../../src/config/db");

const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1"]);
if (!LOOPBACK.has(String(process.env.DB_HOST || "").trim())) {
  console.error("Refusing to seed: DB_HOST is not loopback.");
  process.exit(1);
}

const PASSWORD = "Passw0rd!Test";
const ROUNDS = Math.max(4, parseInt(process.env.BCRYPT_ROUNDS, 10) || 12);

const USERS = [
  { email: "connect@respyr.in",       name: "Respyr Super Admin", role: "super_admin",    code: "RESPYRD01", parent: null },
  { email: "evan@test.local",         name: "Evan Gaudet",        role: "admin",          code: "RESPYRD05", parent: "connect@respyr.in" },
  { email: "owner@ironworks.test",    name: "Iron Works Owner",   role: "facility_admin", code: "TRX1234",   parent: "evan@test.local", facility: true },
  { email: "tanner@ironworks.test",   name: "Tanner Staton",      role: "trainer",        code: "TRN0000001", parent: "owner@ironworks.test", facility: true, split: 50 },
  { email: "sophia@ironworks.test",   name: "Sophia Lee",         role: "trainer",        code: "TRN0000002", parent: "owner@ironworks.test", facility: true, split: 0 },
];

const FACILITY = { name: "Iron Works Gym", code: "TRX1234", admin: "owner@ironworks.test", parentAdmin: "evan@test.local" };

const CLIENTS = [
  { profile_id: "PRF0001", email: "c1@client.test",          name: "Client One",   trainerCode: "TRN0000001" },
  { profile_id: "PRF0002", email: "c2@client.test",          name: "Client Two",   trainerCode: "TRN0000001" },
  { profile_id: "PRF0003", email: "tanner@ironworks.test",   name: "Tanner Staton", trainerCode: "TRN0000001" }, // self
  { profile_id: "PRF0004", email: "c3@client.test",          name: "Client Three", trainerCode: "TRN0000002" },
];

async function main() {
  const hash = await bcrypt.hash(PASSWORD, ROUNDS);
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const emails = USERS.map((u) => u.email);
    const codes = USERS.map((u) => u.code);
    const ph = (arr) => arr.map(() => "?").join(",");

    // Wipe previous seed rows (only ours).
    await conn.execute(`DELETE FROM app_user_roles WHERE user_id IN (${ph(emails)})`, emails);
    await conn.execute(`DELETE FROM table_dietician WHERE email IN (${ph(emails)})`, emails);
    await conn.execute(`DELETE FROM features_allow WHERE dietician_id IN (${ph(codes)})`, codes);
    await conn.execute(`DELETE FROM facilities WHERE partner_code = ?`, [FACILITY.code]);
    await conn.execute(`DELETE FROM table_clients WHERE profile_id IN (${ph(CLIENTS.map((c) => c.profile_id))})`, CLIENTS.map((c) => c.profile_id));

    // Facility first so roles can reference its id.
    const [fRes] = await conn.execute(
      `INSERT INTO facilities (name, partner_code, facility_admin_user_id, parent_admin_user_id, created_by_user_id)
       VALUES (?, ?, ?, ?, ?)`,
      [FACILITY.name, FACILITY.code, FACILITY.admin, FACILITY.parentAdmin, FACILITY.parentAdmin]
    );
    const facilityId = fRes.insertId;

    for (const u of USERS) {
      await conn.execute(
        `INSERT INTO table_dietician (dietician_id, name, phone_no, email, location, logo, dttm, password, is_reset_password)
         VALUES (?, ?, 'NA', ?, 'NA', '', UTC_TIMESTAMP(), ?, 1)`,
        [u.code, u.name, u.email, hash]
      );
      await conn.execute(
        `INSERT INTO app_user_roles
           (user_id, role, partner_code, parent_user_id, facility_id, commission_split_pct,
            status, email_verified_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, 'active', UTC_TIMESTAMP(), UTC_TIMESTAMP(), UTC_TIMESTAMP())`,
        [u.email, u.role, u.code, u.parent, u.facility ? facilityId : null, u.split || 0]
      );
      await conn.execute(
        `INSERT INTO features_allow (dietician_id, test_allow, multiple_reading, practice_test_allow, detailed_scores)
         VALUES (?, 1, 1, 1, 1)`,
        [u.code]
      );
    }

    for (const c of CLIENTS) {
      await conn.execute(
        `INSERT INTO table_clients
           (dietician_id, user_type, profile_id, phone_no, email, profile_name, dob, age, gender,
            height, weight, target_weight, region, location, password, is_dietitian_linked, dttm)
         VALUES (?, 'b2b', ?, 'NA', ?, ?, '1990-01-01', 36, 'M', 175, 80, 75, 'US', 'NA', ?, 1, DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s'))`,
        [c.trainerCode, c.profile_id, c.email, c.name, hash]
      );
    }

    await conn.commit();
    console.log(`Seeded facility #${facilityId} (${FACILITY.name}), ${USERS.length} users, ${CLIENTS.length} clients.`);
    console.log(`Password for all accounts: ${PASSWORD}`);
  } catch (e) {
    await conn.rollback();
    throw e;
  } finally {
    conn.release();
    await pool.end();
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
