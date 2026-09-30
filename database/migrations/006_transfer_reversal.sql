-- 006: record the Stripe transfer reversal that recovered an already-paid
-- commission, so a refund can be traced from invoice to reversal.
ALTER TABLE `commission_entries`
  ADD COLUMN `stripe_reversal_id` VARCHAR(64) NULL AFTER `reversed_by_invoice_id`;
