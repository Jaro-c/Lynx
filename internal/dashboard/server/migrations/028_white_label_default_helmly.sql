-- Rebrand the white-label default from Lynx to Helmly.
-- Only rewrites the untouched factory default; an operator who set their
-- own company_name (anything other than 'Lynx') is left as-is.
ALTER TABLE white_label ALTER COLUMN company_name SET DEFAULT 'Helmly';
UPDATE white_label SET company_name = 'Helmly' WHERE company_name = 'Lynx';
