-- ADD secret function
create or replace function vault_add_secret(
    secret text,
    secret_name text default null,
    description text default null
)
returns uuid
language plpgsql
security definer
as $$
declare
    user_role text;
begin
    user_role := current_setting('role', true);
    if user_role is null or user_role not in ('service_role', 'vault_admin') then
        raise exception 'Insufficient permissions: %', user_role;
    end if;
    return vault.create_secret(secret, secret_name, description);
end;
$$;

-- Read Vault function
create or replace function vault_get_secret(
    secret_name text
)
returns text
language plpgsql
security definer
as $$
declare
    user_role text;
    secret_value text;
begin
    user_role := current_setting('role', true);
    if user_role is null or user_role not in ('service_role', 'vault_admin', 'vault_reader') then
        raise exception 'Insufficient permissions: %', user_role;
    end if;
    select decrypted_secret into secret_value
      from vault.decrypted_secrets
     where name = secret_name
     limit 1;
    return secret_value;
end;
$$;

-- Update secret function
create or replace function vault_update_secret(
    uuid uuid,
    secret text,
    secret_name text default null,
    description text default null
)
returns text
language plpgsql
security definer
as $$
declare
    user_role text;
begin
    user_role := current_setting('role', true);
    if user_role is null or user_role not in ('service_role', 'vault_admin') then
        raise exception 'Insufficient permissions: %', user_role;
    end if;
    perform vault.update_secret(uuid, secret, secret_name, description);
    return 'done';
exception
    when others then
        raise exception 'Update failed (%): %', SQLSTATE, SQLERRM;
end;
$$;

-- Delete postgres function
-- DROP FUNCTION vault_get_secret(text)
-- DROP FUNCTION vault_update_secret(uuid,text,text,text)
