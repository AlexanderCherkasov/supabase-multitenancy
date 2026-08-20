-- 009_rpc_context.sql
-- supabase-multitenancy v0.3.0 — Context discovery & keyset cursor pagination
-- Purpose: Keyset-paginated metadata inspection and client context queries.
-- Dependencies: 006_authorize, 008_rpc_cursor

-- ============================================================================
-- 1. KEYSET PAGINATED CONTEXT
-- ============================================================================

create or replace function multitenancy.context_page(
  p_tenant_id uuid,
  p_section   text,
  p_cursor    text default null,
  p_limit     int default 50
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_uid              uuid := auth.uid();
  v_after            jsonb;
  v_items            jsonb;
  v_next             text;
  v_last             jsonb;
  v_after_key        text;
  v_after_kind       text;
  v_after_id         uuid;
  v_after_created_at timestamptz;
begin
  if v_uid is null then
    raise exception 'UNAUTHENTICATED' using errcode = '28000';
  end if;

  if not exists (
    select 1 from multitenancy.memberships
    where tenant_id = p_tenant_id and user_id = v_uid and status = 'active'
  ) then
    raise exception 'FORBIDDEN' using errcode = '42501';
  end if;

  p_limit := least(greatest(coalesce(p_limit, 50), 1), 100);

  if p_section not in ('permissions', 'roles', 'scopes', 'members', 'invitations', 'audit') then
    raise exception 'INVALID_INPUT: unknown section %', p_section using errcode = '22P02';
  end if;

  if p_section in ('members', 'invitations')
     and not multitenancy.has_access(p_tenant_id, 'multitenancy.members.read', null, 'own') then
    raise exception 'FORBIDDEN' using errcode = '42501';
  end if;

  if p_section = 'audit'
     and not multitenancy.has_access(p_tenant_id, 'multitenancy.audit.read', null, 'own') then
    raise exception 'FORBIDDEN' using errcode = '42501';
  end if;

  v_after := multitenancy._cursor_decode(p_tenant_id, p_section, p_cursor);
  if v_after is not null then
    v_after_key        := v_after->>'key';
    v_after_kind       := v_after->>'kind';
    v_after_id         := (v_after->>'id')::uuid;
    v_after_created_at := (v_after->>'created_at')::timestamptz;
  end if;

  case p_section
    when 'permissions' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.key, x.id), '[]'::jsonb)
      into v_items
      from (
        select id, key, origin, is_deprecated
        from multitenancy.permissions
        where p_cursor is null or (key, id) > (v_after_key, v_after_id)
        order by key, id
        limit p_limit + 1
      ) x;

    when 'roles' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.key, x.id), '[]'::jsonb)
      into v_items
      from (
        select
          rl.id,
          rl.key,
          rl.name,
          rl.description,
          rl.tenant_id,
          (
            select coalesce(
              jsonb_agg(
                jsonb_build_object('key', perm.key, 'access_level', rp.access_level)
                order by perm.key
              ),
              '[]'::jsonb
            )
            from multitenancy.role_permissions rp
            join multitenancy.permissions perm on perm.id = rp.permission_id
            where rp.role_id = rl.id
          ) as permissions
        from multitenancy.roles rl
        where (rl.tenant_id is null or rl.tenant_id = p_tenant_id)
          and (p_cursor is null or (rl.key, rl.id) > (v_after_key, v_after_id))
        order by rl.key, rl.id
        limit p_limit + 1
      ) x;

    when 'scopes' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.kind, x.key, x.id), '[]'::jsonb)
      into v_items
      from (
        select id, kind, key, name
        from multitenancy.scopes
        where tenant_id = p_tenant_id
          and (p_cursor is null or (kind, key, id) > (v_after_kind, v_after_key, v_after_id))
        order by kind, key, id
        limit p_limit + 1
      ) x;

    when 'members' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.created_at, x.id), '[]'::jsonb)
      into v_items
      from (
        select
          mem.id,
          mem.user_id,
          mem.status,
          prof.display_name,
          mem.created_at,
          (
            select coalesce(
              jsonb_agg(jsonb_build_object('role_id', ra.role_id, 'scope_id', ra.scope_id)),
              '[]'::jsonb
            )
            from multitenancy.role_assignments ra
            where ra.membership_id = mem.id
          ) as grants
        from multitenancy.memberships mem
        left join multitenancy.profiles prof on prof.user_id = mem.user_id
        where mem.tenant_id = p_tenant_id
          and (p_cursor is null or (mem.created_at, mem.id) > (v_after_created_at, v_after_id))
        order by mem.created_at, mem.id
        limit p_limit + 1
      ) x;

    when 'invitations' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.created_at desc, x.id desc), '[]'::jsonb)
      into v_items
      from (
        select id, email, email_normalized, expires_at, revoked_at, accepted_at, created_at
        from multitenancy.invitations
        where tenant_id = p_tenant_id
          and (p_cursor is null or (created_at, id) < (v_after_created_at, v_after_id))
        order by created_at desc, id desc
        limit p_limit + 1
      ) x;

    when 'audit' then
      select coalesce(jsonb_agg(to_jsonb(x) order by x.created_at desc, x.id desc), '[]'::jsonb)
      into v_items
      from (
        select id, actor_user_id, command, entity_type, entity_id, payload, created_at
        from multitenancy.audit_events
        where tenant_id = p_tenant_id
          and (p_cursor is null or (created_at, id) < (v_after_created_at, v_after_id))
        order by created_at desc, id desc
        limit p_limit + 1
      ) x;
  end case;

  if jsonb_array_length(v_items) > p_limit then
    v_items := (
      select coalesce(jsonb_agg(value order by ordinality), '[]'::jsonb)
      from jsonb_array_elements(v_items) with ordinality
      where ordinality <= p_limit
    );
    v_last := v_items->(p_limit - 1);
    v_next := multitenancy._cursor_encode(
      p_tenant_id,
      p_section,
      case
        when p_section = 'scopes' then
          jsonb_build_object('kind', v_last->>'kind', 'key', v_last->>'key', 'id', v_last->>'id')
        when p_section in ('permissions', 'roles') then
          jsonb_build_object('key', v_last->>'key', 'id', v_last->>'id')
        else
          jsonb_build_object('created_at', v_last->>'created_at', 'id', v_last->>'id')
      end
    );
  else
    v_next := null;
  end if;

  return jsonb_build_object(
    'api_version', 1,
    'data', jsonb_build_object(
      'items',      v_items,
      'nextCursor', v_next
    )
  );
end;
$$;

revoke all on function multitenancy.context_page(uuid, text, text, int) from public, anon;
grant execute on function multitenancy.context_page(uuid, text, text, int) to authenticated, service_role;


-- ============================================================================
-- 2. CONTEXT HELPER (SINGLE-PAGE OR SELF)
-- ============================================================================

drop function if exists multitenancy.context(uuid, text, text, int);
create or replace function multitenancy.context(
  p_tenant_id uuid,
  p_section   text,
  p_limit     int default 50
)
returns jsonb
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  v_uid    uuid := auth.uid();
  v_result jsonb;
begin
  if p_section <> 'self' then
    return jsonb_build_object(
      'api_version', 1,
      'data', (multitenancy.context_page(p_tenant_id, p_section, null, p_limit))->'data'->'items'
    );
  end if;

  if v_uid is null then
    raise exception 'UNAUTHENTICATED' using errcode = '28000';
  end if;

  if not exists (
    select 1
    from multitenancy.memberships
    where tenant_id = p_tenant_id
      and user_id   = v_uid
      and status    = 'active'
  ) then
    raise exception 'FORBIDDEN' using errcode = '42501';
  end if;

  select jsonb_build_object(
    'tenant', (
      select row_to_json(t)
      from (
        select id, slug, name, owner_user_id, is_active
        from multitenancy.tenants
        where id = p_tenant_id
      ) t
    ),
    'membership', (
      select row_to_json(m)
      from (
        select id, status
        from multitenancy.memberships
        where tenant_id = p_tenant_id
          and user_id   = v_uid
      ) m
    ),
    'is_owner', (
      select (owner_user_id = v_uid)
      from multitenancy.tenants
      where id = p_tenant_id
    )
  ) into v_result;

  return jsonb_build_object(
    'api_version', 1,
    'data',        v_result
  );
end;
$$;

revoke all on function multitenancy.context(uuid, text, int) from public, anon;
grant execute on function multitenancy.context(uuid, text, int) to authenticated, service_role;
