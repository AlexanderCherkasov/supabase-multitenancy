-- 008_rpc_cursor.sql
-- supabase-multitenancy v0.3.0 — Keyset pagination cursor encoding and decoding
-- Purpose: URL-safe Base64 token serialization and deserialization for opaque keyset pagination.
-- Dependencies: 001_base

-- ============================================================================
-- 1. CURSOR DECODER
-- ============================================================================

-- Decode and validate a URL-safe Base64 pagination cursor.
create or replace function multitenancy._cursor_decode(
  p_tenant_id uuid,
  p_section   text,
  p_cursor    text
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_payload  jsonb;
  v_after_id uuid;
begin
  if p_cursor is null then
    return null;
  end if;

  begin
    v_payload := convert_from(
      decode(
        replace(replace(p_cursor, '-', '+'), '_', '/') || repeat('=', (4 - length(p_cursor) % 4) % 4),
        'base64'
      ),
      'utf8'
    )::jsonb;

    if (v_payload->>'v') is distinct from '1'
       or (v_payload->>'tenant_id') is distinct from p_tenant_id::text
       or (v_payload->>'section') is distinct from p_section
       or jsonb_typeof(v_payload->'after') is distinct from 'object' then
      raise exception 'invalid cursor payload structure';
    end if;

    v_after_id := (v_payload#>>'{after,id}')::uuid;
    if v_after_id is null then
      raise exception 'missing cursor id';
    end if;

    if p_section in ('members', 'invitations', 'audit') and (v_payload#>>'{after,created_at}')::timestamptz is null then
      raise exception 'missing cursor timestamp';
    elsif p_section = 'scopes' and (v_payload#>>'{after,kind}' is null or v_payload#>>'{after,key}' is null) then
      raise exception 'missing cursor scope attributes';
    elsif p_section in ('permissions', 'roles') and (v_payload#>>'{after,key}' is null) then
      raise exception 'missing cursor key';
    end if;

    return v_payload->'after';
  exception when others then
    raise exception 'INVALID_CURSOR' using errcode = '22023';
  end;
end;
$$;

revoke all on function multitenancy._cursor_decode(uuid, text, text) from public, anon, authenticated;
grant execute on function multitenancy._cursor_decode(uuid, text, text) to service_role;


-- ============================================================================
-- 2. CURSOR ENCODER
-- ============================================================================

-- Encode a pagination continuation state into a URL-safe Base64 token.
create or replace function multitenancy._cursor_encode(
  p_tenant_id uuid,
  p_section   text,
  p_after     jsonb
)
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select rtrim(
    replace(
      replace(
        replace(
          encode(
            convert_to(
              jsonb_build_object(
                'v',         1,
                'tenant_id', p_tenant_id,
                'section',   p_section,
                'after',     p_after
              )::text,
              'utf8'
            ),
            'base64'
          ),
          E'\n', ''
        ),
        '+', '-'
      ),
      '/', '_'
    ),
    '='
  );
$$;

revoke all on function multitenancy._cursor_encode(uuid, text, jsonb) from public, anon, authenticated;
grant execute on function multitenancy._cursor_encode(uuid, text, jsonb) to service_role;
