LOCK TABLE public.prometheus_cooling_upload_profiles,
           public.prometheus_cooling_upload_receipts IN ACCESS EXCLUSIVE MODE;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM public.prometheus_cooling_upload_profiles) OR
       EXISTS (SELECT 1 FROM public.prometheus_cooling_upload_receipts) THEN
        RAISE EXCEPTION 'cooling upload down migration refuses retained provenance' USING ERRCODE = '55000';
    END IF;
END $$;

DROP TABLE public.prometheus_cooling_upload_receipts;
DROP TABLE public.prometheus_cooling_upload_profiles;
DROP FUNCTION public.prometheus_cooling_upload_receipt_guard();
DROP FUNCTION public.prometheus_cooling_upload_profile_guard();
