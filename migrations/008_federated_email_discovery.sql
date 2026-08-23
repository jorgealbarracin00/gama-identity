CREATE INDEX federated_identities_active_verified_email_lookup_index
  ON federated_identities (lower(provider_email))
  WHERE status = 'active'
    AND provider_email_verified IS TRUE
    AND provider_email IS NOT NULL;
