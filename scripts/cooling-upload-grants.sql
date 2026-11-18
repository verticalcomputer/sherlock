-- Apply with psql -v upload_role=<existing-upload-role> after migration 83.
-- These extend an existing V1 upload role with profile enrollment and receipt
-- writes. Profile revocation remains a database-owner operation.
GRANT SELECT (cluster_id, removed_at) ON public.clusters TO :"upload_role";
GRANT SELECT ON public.prometheus_cooling_upload_profiles,
                public.prometheus_cooling_upload_receipts TO :"upload_role";
GRANT INSERT (profile_id, revision, profile_hash, cluster_id, source_id,
              collector_id, inventory_revision, profile, starts_at, ends_at)
    ON public.prometheus_cooling_upload_profiles TO :"upload_role";
GRANT INSERT (run_id, profile_id, profile_revision, profile_hash, collector_id, payload_hash)
    ON public.prometheus_cooling_upload_receipts TO :"upload_role";
