# Airwallex API notes for Writ

Base URL: `https://api.sandbox.airwallex.com`. Amounts on the wire are major units. Sources: docs/context (doc_*.md, card_create.md, guide.md, SLACK_CONTEXT_NOV9.md). Items marked UNVERIFIED must be checked by the probe and corrected here with the raw fixture name.

## 1. Endpoints we use
| # | Call | Used for | Mode |
|---|------|----------|------|
| 1 | POST /api/v1/authentication/login (headers x-client-id, x-api-key) | bearer token, about 30 min | both |
| 2 | GET /api/v1/issuing/config | remote_auth_settings, spending_limit_settings | both |
| 3 | POST /api/v1/issuing/config/update | turn RA on: remote_auth {enabled, url, default_action, version, new_shared_secret} | RA |
| 4 | GET /api/v1/balances/current | live balance for the reserve check | both |
| 5 | POST /api/v1/simulation/deposit/create | top up if the wallet is empty | both |
| 6 | POST /api/v1/issuing/cardholders/create | one synthetic cardholder (REST field is `type`, MCP uses `cardholder_type`; REST needs name, DOB, address) | both |
| 7 | POST /api/v1/issuing/cards/create | one virtual card per agent, authorization_controls, metadata {team, agent} | both |
| 8 | POST /api/v1/issuing/cards/{id}/update | card_status ACTIVE or INACTIVE, authorization_controls | frozen |
| 9 | GET /api/v1/issuing/cards/{id}/limits | remaining limit, for the console | both |
| 10 | POST /api/v1/simulation/issuing/create | simulated authorization | both |
| 11 | POST /api/v1/simulation/issuing/{transaction_id}/capture, /reverse; POST /api/v1/simulation/issuing/refund | clearing, reversal, refund for ledger tests | both |
| 12 | GET /api/v1/issuing/transactions?card_id=... | read outcome, failure_reason, remote_auth object | both |
| 13 | Our endpoint POST /remote-auth | Airwallex calls it per authorization | RA |

## 2. Card create (card_create.md)
1. Required: `request_id`, `created_by`, `form_factor: "VIRTUAL"`, `is_personalized`, `program`, `cardholder_id`, `authorization_controls`.
2. `authorization_controls`: `allowed_transaction_count` SINGLE or MULTIPLE (immutable once set, use MULTIPLE so frozen mode can rearm), `transaction_limits` {currency, limits: [{amount, interval}]} with intervals PER_TRANSACTION, DAILY, WEEKLY, MONTHLY, QUARTERLY, YEARLY, ALL_TIME, `allowed_currencies`, `allowed_merchant_categories`, `active_from`, `active_to`.
3. `metadata`: up to 20 keys, values up to 150 chars. Put team, agent and the current writ hash prefix here.
4. Checked on the US sandbox, Mon Nov 9: send `program: { purpose: "COMMERCIAL" }` only. The response fills `sub_type: GOOD_FUNDS_CREDIT` and `type: CREDIT`. Sending `sub_type` ourselves returns "Unsupported program sub type". All cards are Visa. A DELEGATE cardholder cannot back a personalized card. Use `type: INDIVIDUAL` with name, date of birth, address and `express_consent_obtained: "yes"`.
5. Virtual cards activate on their own. Create returns PENDING, then GET shows ACTIVE. Update to INACTIVE fails while the card is PENDING ("Invalid status update") and succeeds once it is ACTIVE. Create does not take `card_status`.
6. A limit above `spending_limit_settings.per_transaction_limits[].maximum` makes create or update fail. Read it first.

## 3. Arm and disarm (frozen mode)
1. Arm: update with `card_status: "ACTIVE"` and authorization_controls: PER_TRANSACTION and ALL_TIME equal to the writ amount, `allowed_currencies: [writ.currency]`, `allowed_merchant_categories: [writ.mcc]`, `active_to` equal to writ expiry.
2. UNVERIFIED: whether ALL_TIME counts spend from before the rearm. If it does, set ALL_TIME to prior spend plus the writ amount. The probe must test two arms in a row.
3. Disarm: update with `card_status: "INACTIVE"` after the transaction read, after taint, and on writ expiry. Retry with backoff, alert if it still fails.
4. Bank side refusals we expect: CARD_INACTIVE, LIMIT_EXCEEDED, MERCHANT_CATEGORY_NOT_ALLOWED, CURRENCY_NOT_ALLOWED, OUT_OF_ALLOWED_TIME_RANGE, INSUFFICIENT_FUNDS, CARD_CLOSED.

## 4. Simulation
1. Body: `card_id`, `transaction_amount` or `amount` (UNVERIFIED which), `transaction_currency` or `currency` (UNVERIFIED), `merchant_category_code` (4 digit Visa MCC), `merchant_info` (name and more), optional `transaction_failure_reason`. Check the field names against the live docs or the docs MCP at mcp.sandbox.airwallex.com before coding, then save the raw call in fixtures/.
2. Cannot set merchant.id. Match on MCC and name.
3. Max 9,999.99 per authorization, 11 currencies allowed. Use USD only.
4. Read results with GET /api/v1/issuing/transactions. Use type and status together (airwallexdev.com, Nov 9): AUTHORIZATION plus PENDING means funds held, CLEARING plus APPROVED means debited, CLEARING plus FAILED means declined (read `failure_reason`). `transaction_type: CLEARING` alone does not mean accepted. Do not wait for APPROVED on an authorization.
5. The simulation API had outages Oct 27 to 30. Check status.airwallex.com if it says "failed to process transaction".

## 5. Remote Authorization
1. Enablement: Turner Vickery (Airwallex, Slack U0CCF5PN6NN) enables on DM with the account id or client id. Account also needs flag ISS_AUTH_REMOTE_AUTH_ENABLED.
2. Configure: POST /api/v1/issuing/config/update, body `{"remote_auth": {"enabled": true, "url": "https://<tunnel>/remote-auth", "default_action": "DECLINED", "version": 2, "new_shared_secret": true}}`. The shared secret is returned once. Put it in `.env` as AIRWALLEX_RA_SHARED_SECRET.
3. Request (version 2) fields we use: `card_id`, `card_transaction_event_id`, `card_transaction_id`, `transaction_type` (AUTHORIZATION, and possibly CLEARING), `transaction_category`, `transaction_amount`, `transaction_currency`, `merchant.name`, `merchant.category_code`, `merchant.country`, `billing_order`, `masked_card_number` (log only last 4).
4. Signature: headers `x-nonce` ("<epoch ms>.<random>") and `x-signature` = base64(HMAC_SHA256(shared_secret, x-nonce)). The body is not signed. Use a constant time compare, a 30 s freshness window and a seen nonce cache.
5. Response within 2.5 s: `{"card_transaction_event_id": "<echo>", "response_status": "AUTHORIZED" | "DECLINED", "status_reason": "<our code>"}`. A mismatched id, timeout, error or non JSON triggers default_action.
6. Airwallex can still decline after we approve (its own risk checks).
7. Verify: after a simulated swipe, the transaction carries a `remote_auth` object. `default_action_used: false` plus our status_reason means it works. `default_action_used: true` with TIMEOUT or ERROR means it called us and we failed.
8. UNVERIFIED: whether simulation passes our merchant_info into the RA payload, or shows the test generator merchant ("CARD_TX_GENERATOR REMOTE", country AWX). If it does not, bind on MCC and amount only and say so.
9. An IP allowlist that blocks Airwallex causes timeouts. RA source IPs are not published.

## 6. Transaction lifecycle (doc_transaction-lifecycle.md)
1. Three levels: lifecycle (no status), card transaction (has a terminal status), transaction event (type and subtype).
2. Use card transaction `billing_amounts` (total_pending, total_debited, total_credited, total_expired, total_reversed) to reconcile the ledger.
3. Ledger must handle: authorization, clearing (possibly several per auth, possibly a different amount), reversal, expiry, refund, and forced capture with no prior auth.

## 7. Limits and habits
1. Rate limits: 20 req/s global, 10 req/s per endpoint, concurrency 10, auth endpoint 100 per minute.
2. request_id: new UUID per operation, reuse only on retry of the same one. Reuse within 7 days for a different operation returns duplicate_request_id.
3. Sandbox wallets are pre-funded (10M per currency). Organizers OK a ring-fenced budget (for example USD 25,000) inside it for the reserve scene.
4. No KYB needed for sandbox keys. Keys: sandbox.airwallex.com, Account > Developer > API keys.
5. Staff will not promise sandbox stability through Nov 19. Record early.
