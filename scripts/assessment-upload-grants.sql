-- Apply with psql -v assessment_role=<dedicated-upload-assessment-login>
-- after migration 83 and assessment-grants.sql.
GRANT SELECT ON public.prometheus_cooling_upload_profiles,
                public.prometheus_cooling_upload_receipts TO :"assessment_role";
