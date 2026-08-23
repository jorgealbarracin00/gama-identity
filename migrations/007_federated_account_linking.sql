CREATE UNIQUE INDEX federated_identities_active_human_provider_unique
  ON federated_identities (human_identity_id, provider)
  WHERE status = 'active';
