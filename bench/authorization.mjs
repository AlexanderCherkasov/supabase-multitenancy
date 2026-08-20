#!/usr/bin/env node
/**
 * Reproducible RLS Authorization & Overhead Benchmark
 *
 * Runs micro-benchmarks and scaled dataset queries against local PostgreSQL
 * to measure exact authorization evaluation latency and RLS query overhead.
 *
 * Usage:
 *   node bench/authorization.mjs
 *   npm run benchmark
 */
import { execFileSync } from "node:child_process";
import os from "node:os";

const DB_URL = process.env.SUPABASE_DB_URL || "postgresql://postgres:postgres@127.0.0.1:54322/postgres";

function psql(query) {
  return execFileSync("psql", [DB_URL, "-X", "-v", "ON_ERROR_STOP=1", "-At", "-c", query], {
    encoding: "utf8",
    maxBuffer: 50 * 1024 * 1024,
  }).trim();
}

function psqlJson(query) {
  const result = psql(query);
  const lines = result.split("\n").map((l) => l.trim()).filter(Boolean);
  return JSON.parse(lines[lines.length - 1]);
}

function calcStats(samples) {
  if (!samples.length) return null;
  const sorted = [...samples].sort((a, b) => a - b);
  const n = sorted.length;
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  const mean = sum / n;
  const variance = sorted.reduce((acc, v) => acc + Math.pow(v - mean, 2), 0) / n;
  const stddev = Math.sqrt(variance);

  const p = (pct) => {
    const idx = Math.min(Math.floor((pct / 100) * n), n - 1);
    return sorted[idx];
  };

  return {
    n,
    min: Number(sorted[0].toFixed(4)),
    p50: Number(p(50).toFixed(4)),
    p90: Number(p(90).toFixed(4)),
    p95: Number(p(95).toFixed(4)),
    p99: Number(p(99).toFixed(4)),
    max: Number(sorted[n - 1].toFixed(4)),
    mean: Number(mean.toFixed(4)),
    stddev: Number(stddev.toFixed(4)),
  };
}

async function main() {
  console.log("================================================================================");
  console.log("  SUPABASE-MULTITENANCY: REPRODUCIBLE RLS & AUTHORIZATION BENCHMARK");
  console.log("================================================================================");

  const pgVersion = psql("select version();").split("\n")[0];
  console.log(`Environment:`);
  console.log(`  OS / Hardware:     ${os.type()} ${os.arch()} (${os.cpus()[0]?.model || "CPU"})`);
  console.log(`  PostgreSQL:        ${pgVersion}`);
  console.log(`  Database URL:      ${DB_URL}`);
  console.log("");

  console.log("--> Setting up test tenant, users, scopes, and benchmark schema...");

  const setupSql = `
  create or replace function public._bench_setup() returns jsonb language plpgsql as $$
  declare
    v_owner_id uuid := '10000000-0000-0000-0000-000000000001'::uuid;
    v_manager_id uuid := '10000000-0000-0000-0000-000000000002'::uuid;
    v_writer_id uuid := '10000000-0000-0000-0000-000000000003'::uuid;
    v_outsider_id uuid := '10000000-0000-0000-0000-000000000004'::uuid;
    v_tenant_id uuid;
    v_scope_id uuid;
    v_manager_mem_id uuid;
    v_writer_mem_id uuid;
    v_manager_role_id uuid;
    v_writer_role_id uuid;
  begin
    insert into auth.users (id, email, encrypted_password, email_confirmed_at, raw_app_meta_data, raw_user_meta_data, created_at, updated_at, role, aud)
    values
      (v_owner_id, 'bench-owner@test.com', 'pwd', now(), '{"provider":"email"}', '{}', now(), now(), 'authenticated', 'authenticated'),
      (v_manager_id, 'bench-manager@test.com', 'pwd', now(), '{"provider":"email"}', '{}', now(), now(), 'authenticated', 'authenticated'),
      (v_writer_id, 'bench-writer@test.com', 'pwd', now(), '{"provider":"email"}', '{}', now(), now(), 'authenticated', 'authenticated'),
      (v_outsider_id, 'bench-outsider@test.com', 'pwd', now(), '{"provider":"email"}', '{}', now(), now(), 'authenticated', 'authenticated')
    on conflict (id) do nothing;

    insert into multitenancy.profiles (user_id, display_name)
    values
      (v_owner_id, 'Bench Owner'),
      (v_manager_id, 'Bench Manager'),
      (v_writer_id, 'Bench Writer'),
      (v_outsider_id, 'Bench Outsider')
    on conflict (user_id) do nothing;

    insert into multitenancy.tenants (slug, name, owner_user_id)
    values ('bench-tenant', 'Benchmark Tenant', v_owner_id)
    on conflict (slug) do update set owner_user_id = v_owner_id
    returning id into v_tenant_id;

    insert into multitenancy.scopes (tenant_id, kind, key, name)
    values (v_tenant_id, 'project', 'main', 'Main Project')
    on conflict (tenant_id, kind, key) do update set name = 'Main Project'
    returning id into v_scope_id;

    insert into multitenancy.memberships (tenant_id, user_id, status)
    values
      (v_tenant_id, v_owner_id, 'active'),
      (v_tenant_id, v_manager_id, 'active'),
      (v_tenant_id, v_writer_id, 'active')
    on conflict (tenant_id, user_id) do update set status = 'active';

    select id into v_manager_mem_id from multitenancy.memberships where tenant_id = v_tenant_id and user_id = v_manager_id;
    select id into v_writer_mem_id from multitenancy.memberships where tenant_id = v_tenant_id and user_id = v_writer_id;

    insert into multitenancy.roles (key, name, description)
    values ('bench_manager', 'Bench Manager', 'Tenant manager all permissions')
    on conflict (key) where tenant_id is null do update set name = excluded.name;

    insert into multitenancy.roles (key, name, description)
    values ('bench_writer', 'Bench Writer', 'Project writer scoped')
    on conflict (key) where tenant_id is null do update set name = excluded.name;

    select id into v_manager_role_id from multitenancy.roles where key = 'bench_manager' and tenant_id is null;
    select id into v_writer_role_id from multitenancy.roles where key = 'bench_writer' and tenant_id is null;

    insert into multitenancy.role_permissions (role_id, permission_id, access_level)
    select v_manager_role_id, id, 'all' from multitenancy.permissions where key in ('documents.read', 'documents.update', 'documents.delete')
    on conflict (role_id, permission_id) do update set access_level = 'all';

    insert into multitenancy.role_permissions (role_id, permission_id, access_level)
    select v_writer_role_id, id, 'own' from multitenancy.permissions where key in ('documents.read', 'documents.update')
    on conflict (role_id, permission_id) do update set access_level = 'own';

    insert into multitenancy.role_assignments (tenant_id, membership_id, role_id, scope_id)
    values
      (v_tenant_id, v_manager_mem_id, v_manager_role_id, null),
      (v_tenant_id, v_writer_mem_id, v_writer_role_id, v_scope_id)
    on conflict do nothing;

    return jsonb_build_object(
      'tenant_id', v_tenant_id,
      'scope_id', v_scope_id,
      'owner_id', v_owner_id,
      'manager_id', v_manager_id,
      'writer_id', v_writer_id,
      'outsider_id', v_outsider_id
    );
  end;
  $$;
  select public._bench_setup();
  `;

  const setupInfo = psqlJson(setupSql);
  const { tenant_id, scope_id, owner_id, manager_id, writer_id, outsider_id } = setupInfo;

  console.log("  Setup complete. Running micro-benchmarks...");
  console.log("");

  // 1. Direct authorization latency
  console.log("--------------------------------------------------------------------------------");
  console.log("  1. Direct Function Evaluation: api.access_level()");
  console.log("     (100 warm-up runs + 200 sample iterations per role tier)");
  console.log("--------------------------------------------------------------------------------");

  const runnerSql = `
  create or replace function public._bench_eval(p_uid uuid, p_tid uuid, p_perm text, p_scopes uuid[], p_iters int)
  returns jsonb language plpgsql as $$
  declare
    t0 timestamptz;
    t1 timestamptz;
    i int;
    res text;
    times float[] := array[]::float[];
  begin
    perform set_config('request.jwt.claim.sub', p_uid::text, true);
    perform set_config('role', 'authenticated', true);

    -- Warm-up
    for i in 1..100 loop
      res := api.access_level(p_tid, p_perm, p_scopes);
    end loop;

    -- Timed sample iterations
    for i in 1..p_iters loop
      t0 := clock_timestamp();
      res := api.access_level(p_tid, p_perm, p_scopes);
      t1 := clock_timestamp();
      times := array_append(times, (extract(epoch from (t1 - t0)) * 1000.0)::float);
    end loop;

    return to_jsonb(times);
  end;
  $$;
  `;
  psql(runnerSql);

  const tiers = [
    { label: "Tenant Owner (is_owner exit)", uid: owner_id, scopes: `array['${scope_id}']::uuid[]` },
    { label: "Outsider (non-member exit)", uid: outsider_id, scopes: `array['${scope_id}']::uuid[]` },
    { label: "Writer (scoped 'own' check)", uid: writer_id, scopes: `array['${scope_id}']::uuid[]` },
    { label: "Manager (tenant-wide 'all')", uid: manager_id, scopes: `null::uuid[]` },
  ];

  console.log(
    "User Tier".padEnd(35) +
    "Access Level".padEnd(15) +
    "p50 (ms)".padEnd(12) +
    "p95 (ms)".padEnd(12) +
    "Mean (ms)".padEnd(12) +
    "Throughput"
  );
  console.log("-".repeat(95));

  for (const tier of tiers) {
    const rawTimes = psqlJson(`select public._bench_eval('${tier.uid}', '${tenant_id}', 'documents.read', ${tier.scopes}, 200);`);
    const stats = calcStats(rawTimes);
    const accessLevel = psql(`
      select set_config('request.jwt.claim.sub', '${tier.uid}', true);
      select set_config('role', 'authenticated', true);
      select api.access_level('${tenant_id}', 'documents.read', ${tier.scopes});
    `).split("\n").pop();

    const opsSec = stats.mean > 0 ? `~${Math.round(1000 / stats.mean).toLocaleString()} checks/s` : "N/A";
    console.log(
      tier.label.padEnd(35) +
      accessLevel.padEnd(15) +
      stats.p50.toFixed(4).padEnd(12) +
      stats.p95.toFixed(4).padEnd(12) +
      stats.mean.toFixed(4).padEnd(12) +
      opsSec
    );
  }
  console.log("");

  // 2. Scaled dataset queries (100k rows)
  console.log("--------------------------------------------------------------------------------");
  console.log("  2. End-to-End Query Latency & RLS Overhead (100,000 Rows)");
  console.log("--------------------------------------------------------------------------------");

  console.log("--> Generating 100,000 benchmark records in public.bench_documents...");
  const tableSetupSql = `
  drop table if exists public.bench_documents cascade;
  create table public.bench_documents (
    id uuid primary key default gen_random_uuid(),
    tenant_id uuid not null references multitenancy.tenants(id) on delete cascade,
    project_id uuid null,
    author_id uuid not null references auth.users(id),
    title text not null,
    created_at timestamptz not null default now()
  );

  insert into public.bench_documents (tenant_id, project_id, author_id, title)
  select
    '${tenant_id}'::uuid,
    case when i % 3 = 0 then '${scope_id}'::uuid else null end,
    case when i % 5 = 0 then '${writer_id}'::uuid else '${owner_id}'::uuid end,
    'Benchmark Document ' || i
  from generate_series(1, 100000) as i;

  create index idx_bench_docs_tenant_project on public.bench_documents(tenant_id, project_id);
  create index idx_bench_docs_author on public.bench_documents(author_id);
  analyze public.bench_documents;

  alter table public.bench_documents enable row level security;
  grant select on public.bench_documents to authenticated;

  drop policy if exists "bench_docs_select" on public.bench_documents;
  create policy "bench_docs_select" on public.bench_documents
  for select to authenticated
  using (
    case api.access_level(tenant_id, 'documents.read', array[project_id])
      when 'all' then true
      when 'own' then author_id = auth.uid()
      else false
    end
  );
  `;
  psql(tableSetupSql);

  const testTargetId = psql(`select id from public.bench_documents where author_id = '${writer_id}' and project_id = '${scope_id}' limit 1;`);

  console.log(`  Sample document PK: ${testTargetId}`);
  console.log("");

  const queryBenchmarkSql = `
  create or replace function public._bench_query_explain(p_uid uuid, p_sql text, p_iters int)
  returns jsonb language plpgsql as $$
  declare
    t0 timestamptz;
    t1 timestamptz;
    i int;
    times float[] := array[]::float[];
  begin
    perform set_config('request.jwt.claim.sub', p_uid::text, true);
    perform set_config('role', 'authenticated', true);

    -- Warm-up
    for i in 1..20 loop
      execute p_sql;
    end loop;

    -- Timed iterations
    for i in 1..p_iters loop
      t0 := clock_timestamp();
      execute p_sql;
      t1 := clock_timestamp();
      times := array_append(times, (extract(epoch from (t1 - t0)) * 1000.0)::float);
    end loop;

    return to_jsonb(times);
  end;
  $$;
  `;
  psql(queryBenchmarkSql);

  const queries = [
    {
      name: "PK Lookup: Baseline (No RLS, direct ID)",
      uid: owner_id,
      sql: `select count(*) from (select * from public.bench_documents where id = '${testTargetId}') x`,
      rls: false,
    },
    {
      name: "PK Lookup: Supabase-MT (Manager 'all')",
      uid: manager_id,
      sql: `select count(*) from (select * from public.bench_documents where id = '${testTargetId}') x`,
      rls: true,
    },
    {
      name: "PK Lookup: Supabase-MT (Writer 'own')",
      uid: writer_id,
      sql: `select count(*) from (select * from public.bench_documents where id = '${testTargetId}') x`,
      rls: true,
    },
    {
      name: "PK Lookup: Outsider Attempt (Denied)",
      uid: outsider_id,
      sql: `select count(*) from (select * from public.bench_documents where id = '${testTargetId}') x`,
      rls: true,
    },
    {
      name: "50-Row Scan: Baseline (Direct tenant filter)",
      uid: owner_id,
      sql: `select count(*) from (select * from public.bench_documents where tenant_id = '${tenant_id}' limit 50) x`,
      rls: false,
    },
    {
      name: "50-Row Scan: Supabase-MT (Manager 'all')",
      uid: manager_id,
      sql: `select count(*) from (select * from public.bench_documents where tenant_id = '${tenant_id}' limit 50) x`,
      rls: true,
    },
  ];

  console.log(
    "Query Scenario".padEnd(45) +
    "p50 (ms)".padEnd(12) +
    "p95 (ms)".padEnd(12) +
    "Mean (ms)".padEnd(12) +
    "QPS"
  );
  console.log("-".repeat(85));

  for (const q of queries) {
    if (!q.rls) {
      psql(`alter table public.bench_documents disable row level security;`);
    } else {
      psql(`alter table public.bench_documents enable row level security;`);
    }

    const rawTimes = psqlJson(`select public._bench_query_explain('${q.uid}', '${q.sql.replace(/'/g, "''")}', 100);`);
    const stats = calcStats(rawTimes);
    const qps = stats.mean > 0 ? `~${Math.round(1000 / stats.mean).toLocaleString()} QPS` : "N/A";

    console.log(
      q.name.padEnd(45) +
      stats.p50.toFixed(4).padEnd(12) +
      stats.p95.toFixed(4).padEnd(12) +
      stats.mean.toFixed(4).padEnd(12) +
      qps
    );
  }

  // Cleanup benchmark artifacts
  console.log("");
  console.log("--> Cleaning up benchmark temporary tables and helper functions...");
  psql(`
    drop table if exists public.bench_documents cascade;
    drop function if exists public._bench_setup();
    drop function if exists public._bench_eval(uuid, uuid, text, uuid[], int);
    drop function if exists public._bench_query_explain(uuid, text, int);
  `);

  console.log("================================================================================");
  console.log("  BENCHMARK FINISHED SUCCESSFULLY");
  console.log("================================================================================");
}

main().catch((err) => {
  console.error("Benchmark failed:", err);
  process.exit(1);
});
