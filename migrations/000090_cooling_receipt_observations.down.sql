SET LOCAL lock_timeout = '1s';
DROP TRIGGER prometheus_cooling_upload_receipt_observation_proof ON public.prometheus_cooling_upload_receipts;
DROP TRIGGER cooling_observation_locator_insert ON public.observations;
DROP TRIGGER cooling_observation_locator_update ON public.observations;
DROP FUNCTION public.cooling_receipt_observation_proof();
DROP FUNCTION public.cooling_observation_locator();
DROP TABLE public.prometheus_cooling_receipt_observations;
ALTER TABLE public.prometheus_cooling_upload_receipts DROP COLUMN observation_lookup_complete;
