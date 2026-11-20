-- Compatibility step for installations upgrading from 88. Version 90 supplies
-- the receipt lookup without an index build on the observations archive.
-- Installations that already applied the original 89 skip this version.
SELECT 1;
