# Resend templates — order page payment emails

Sent by `src/services/paymentEmails.js`. Create each one in Resend
(Templates → Create template → paste the HTML), publish it, and put its
template ID (or the slug you named it) in the Lambda environment. Without the
env var the code sends the same content as inline HTML, so nothing breaks
before the templates exist.

| Template file            | Env var                             | Suggested name / slug | Sent on                                                            |
|--------------------------|-------------------------------------|-----------------------|--------------------------------------------------------------------|
| `payment_received.html`  | `RESEND_PAYMENT_RECEIPT_TEMPLATE_ID` | `payment_received`    | `checkout.session.completed`                                       |
| `payment_failed.html`    | `RESEND_PAYMENT_FAILED_TEMPLATE_ID`  | `payment_failed`      | `payment_intent.payment_failed`, `checkout.session.async_payment_failed` |
| `renewal_failed.html`    | `RESEND_RENEWAL_FAILED_TEMPLATE_ID`  | `renewal_failed`      | `invoice.payment_failed` (month 2+)                                |

Subject and from are set by the code on every send (they override the
template's defaults), so the subject you type in Resend is just a placeholder.

## Variables

Resend returns 422 if a template references a variable that is not supplied,
so the code always sends every variable below — with `—` or an empty string
when there is nothing to show. Do not add variables to the template without
adding them to `paymentEmails.js`. Values are already HTML-escaped by the
code; use triple braces `{{{VAR}}}` so Resend does not escape them twice.

### payment_received
| Variable            | Example                                      |
|---------------------|----------------------------------------------|
| `MEMBER_NAME`       | `Sam Lee` (falls back to `there`)            |
| `AMOUNT_PAID`       | `$29.00`                                     |
| `PLAN`              | `Rysflo Membership · $29.00/month`           |
| `REFERRAL_CODE`     | `TRN7OBZ1FT` or `—`                          |
| `PAID_ON`           | `September 16, 2026`                         |
| `NEXT_BILLING_DATE` | `October 16, 2026` or `—`                    |
| `SHIP_TO`           | `12 Main St, Austin, TX, 78701` or `—`       |
| `APP_CODE_NOTE`     | `Your Rysflo Referral Code for the app is in a separate email — you'll need it when you create your account.` or, for an already-linked app user, `Open the Rysflo app and sign in with this email address — your purchase is already linked to your account.` |
| `SUPPORT_EMAIL`     | `support@rysflo.com` (`SUPPORT_EMAIL` env)   |

### payment_failed
| Variable        | Example                                                        |
|-----------------|----------------------------------------------------------------|
| `AMOUNT`        | `$29.00`                                                       |
| `REASON`        | Stripe's decline message, e.g. `Your card was declined.`       |
| `RETRY_URL`     | `https://admin.rysflo.com/order/TRN7OBZ1FT` (`ORDER_CANCEL_URL` env + code) |
| `SUPPORT_EMAIL` | `support@rysflo.com`                                           |

### renewal_failed
| Variable        | Example                                     |
|-----------------|---------------------------------------------|
| `AMOUNT`        | `$29.00`                                    |
| `REASON`        | `Your card was declined.`                   |
| `SUPPORT_EMAIL` | `support@rysflo.com`                        |

## Stripe side

The webhook endpoint must be subscribed to `payment_intent.payment_failed`,
`invoice.payment_failed` and `checkout.session.async_payment_failed` in
addition to the events it already receives, or the failure emails never fire.
