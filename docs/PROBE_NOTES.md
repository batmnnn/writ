# Probe notes

Run: `bun run probe` against the US sandbox, Mon Nov 9, 16:12 IST. Frozen mode. All five expected outcomes matched. Raw responses are in fixtures/, with card numbers, tokens and any 13 to 19 digit run removed. Summary in fixtures/probe_summary.json.

## Results
| Step | Expected | Got | Fixture |
|------|----------|-----|---------|
| Swipe 40 USD, armed 50 | approved authorization | AUTHORIZATION, process_result APPROVED | swipe_40_pass.json |
| Capture that 40 USD | CLEARING plus APPROVED | CLEARING plus APPROVED | capture_40.json |
| Swipe 60 USD, armed 50 | LIMIT_EXCEEDED | LIMIT_EXCEEDED | swipe_60_limit.json |
| Rearm 50, swipe 50 | record | LIMIT_EXCEEDED | swipe_50_after_rearm.json |
| Disarm, swipe 10 USD | CARD_INACTIVE | CARD_INACTIVE | swipe_10_inactive.json |
| Swipe MCC 5999, armed for 5734 | MERCHANT_CATEGORY_NOT_ALLOWED | MERCHANT_CATEGORY_NOT_ALLOWED | swipe_mcc_5999.json |

## Findings
1. Remote Authorization: `remote_auth_settings` is not in GET /api/v1/issuing/config. RA is not enabled on this account. Frozen mode is the only mode that runs today. Fixture: issuing_config.json.
2. USD cap: `spending_limit_settings.per_transaction_limits` USD default 10,000, maximum 50,000 (major units). Demo amounts are far below it.
3. Balance: USD available_amount about 10,000,000. Approved authorizations and clearings from the probe reduce it by a few dollars per run. Fixture: balance.json.
4. Card start status: create returns PENDING. GET shows PENDING for 1 to 3 seconds, then ACTIVE. The update to INACTIVE succeeds once ACTIVE. Fixture: card_create.json.
5. ALL_TIME counts old spend. After 40 USD was spent under ALL_TIME 50, a rearm that sets ALL_TIME to 50 again still refused a 50 USD swipe with LIMIT_EXCEEDED. So the limit is lifetime spend on the card, not spend since the last update. Arm must set ALL_TIME to prior card spend plus the writ amount, and PER_TRANSACTION to the writ amount. The current `arm()` sets both to the writ amount, which is only right for the first arm of a card. Fix this in the arm caller, or give each writ a fresh card.
6. Card reads carry `card_number`. GET /api/v1/issuing/cards/{id} and the update response both include a `card_number` field. The adapter drops it and keeps only the last 4. Never log a raw card read.
7. Card update takes `request_id` in the body (200 with it). The docs list it only in the response, but the live API accepts it.

## Simulation field names that worked
1. POST /api/v1/simulation/issuing/create with `card_id`, `transaction_amount` (major units), `transaction_currency`, `merchant_category_code`, `merchant_info`. Not `amount` or `currency`.
2. The response uses the new transaction model: `type`, `subtype`, `process_result` (APPROVED or DECLINED), `failure_reason`, `card_transaction_id`, `card_transaction_event_id`, `card_transaction_lifecycle_id`. It does not carry `transaction_type` or `status`.
3. A decline comes back as HTTP 201 with `process_result: DECLINED` and `failure_reason`, not as an HTTP error.
4. Capture: POST /api/v1/simulation/issuing/card_transaction_lifecycles/{card_transaction_lifecycle_id}/capture with `transaction_amount` and `merchant_info`. Returns `type: CLEARING`, `process_result: APPROVED`.
5. `merchant_info` lands as `merchant.name`, padded with underscores to 25 characters ("WRIT PROBE SOFTWARE______"). City is 13 underscores and country is empty. Merchant name match must strip trailing underscores and spaces.
6. The capture sets the clearing MCC to 7531, not the authorization MCC. Do not match clearings on MCC. Match them on `card_transaction_lifecycle_id`.
7. Without `merchant_info` on the capture, the clearing shows the generator merchant ("AIRPRO_TX_GENERATOR", AUS, 7531).

## Transaction reads
1. GET /api/v1/issuing/transactions?card_id= (legacy model). Declines show as AUTHORIZATION plus FAILED with `failure_reason`. A captured swipe shows CLEARING plus APPROVED. Amounts are negative for debits (-40).
2. `single_phase: true` is accepted but does not clear: the swipe stayed an authorization with 40 pending, and a later capture left two CLEARING APPROVED rows for one 40 USD debit in the legacy list. The probe does not use `single_phase`.
3. GET /api/v1/issuing/card_transactions?card_id= gives one row per swipe with `status` (AUTHORIZED, CLEARED, DECLINED) and `transaction_amounts` (total_authorized, total_pending, total_debited and so on). Reconcile the ledger from this, not by summing legacy rows.

## Sandbox stability
1. Between 16:07 and 16:12 IST every simulation call failed with HTTP 400 `bad_request: failed to process transaction`, for every payload and on cards that had worked minutes before. Two calls then timed out at 5 s. It recovered by itself after about 4.5 minutes. If the probe fails with this message, wait and rerun. Do not change the payload.
2. The demo should retry a simulation once on that error before it reports a decline.
