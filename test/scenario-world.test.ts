// Scenario world for Writ. These are decide() cases, not 100 separate news stories.
//
// Verified sources, checked against the live web on Thu Nov 12, 2026:
// - Washington Post, Feb 7, 2025. Geoffrey Fowler. Operator bought eggs for $31.43 on Instacart
//   after he asked it to find cheap eggs. https://www.washingtonpost.com/technology/2025/02/07/openai-operator-ai-agent-chatgpt/
//   Also logged as AI Incident 1028: https://incidentdatabase.ai/cite/1028/
// - OpenAI Operator system card. Purchases are supposed to require confirmation.
//   https://openai.com/index/operator-system-card/
// - Reddit r/aiagents, Jul 17, 2026. People who have completed agent checkout, and the fear it spends.
//   https://www.reddit.com/r/aiagents/comments/1uz64z1/has_anyone_actually_completed_a_purchase_with/
// - Reddit r/ChatGPTPro, Nov 23, 2025. A user used agent mode to buy coffee on Amazon.
//   https://www.reddit.com/r/ChatGPTPro/comments/1p4qafw/would_you_trust_ai_to_shop_for_you/
// - Reddit r/ClaudeCode, Mar 18, 2026. A $25 virtual debit card was given to an agent. Zero purchases completed.
//   https://www.reddit.com/r/ClaudeCode/comments/1rxc0jp/i_gave_my_ai_agent_a_debit_card_and_told_it_to/
// - Reddit r/aiagents, Jun 6, 2026. Double buy, spend loops, and manual approval over $5.
//   https://www.reddit.com/r/aiagents/comments/1txns8d/is_anybody_actually_using_agents_to_buy_things_yet/
// - Reddit r/AutoGPT, May 5, 2026. Prompt injection, wrong vendor, retries, hidden subscriptions.
//   https://www.reddit.com/r/AutoGPT/comments/1t1m9sk/how_are_you_guys_handling_payments_for_autonomous/
// - Reddit r/AI_Agents, Apr 20, 2026. Right merchant, wrong booking. Three small rooms instead of one.
//   https://www.reddit.com/r/AI_Agents/comments/1sr1vu2/how_are_you_handling_agents_that_actually_spend/
// - Infosecurity Magazine. Barracuda: hidden text in an invoice email telling an assistant to change payment details.
//   https://www.infosecurity-magazine.com/news/attackers-hide-ai-prompt/
// - Invariant Labs, Apr 1, 2025 and May 26, 2025. MCP tool poisoning and a GitHub issue that hijacks the agent.
//   https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks
//   https://invariantlabs.ai/blog/mcp-github-vulnerability
// - Ramp agent cards and Mercury agent cards. A human sets the limit. The agent cannot raise it.
//   https://ramp.com/blog/virtual-cards-for-ai-agents
//   https://support.mercury.com/hc/en-us/articles/51299754284948-Agent-cards-Giving-AI-agents-a-card-of-their-own
// - PYMNTS, Nov 2026. Fintechs handing agents a company card.
//   https://www.pymnts.com/news/artificial-intelligence/2026/fintechs-hand-ai-agents-the-company-card/
// - Payments Dive. Fraud, chargeback, and prompt injection as open questions, not a counted loss.
//   https://www.paymentsdive.com/news/ai-commerce-portends-potential-fraud/760426/
//
// Added after a web check of X mirrors on Thu Nov 12, 2026. The X reader could not use X search.
// - May 4, 2026. A Morse-code reply got Grok to tag Bankr, which sent 3 billion DRB
//   (about $150,000 to $200,000) to ilhamrafli.base.eth. Base tx cited by SlowMist and BeInCrypto.
//   https://beincrypto.com/grok-wallet-bankr-drb-prompt-injection/
//   https://slowmist.medium.com/behind-the-grok-exploitation-an-analysis-of-ai-agent-permission-chain-abuse-4d832d1bfc73
//   https://airisk.mit.edu/ai-incidents/1556-x-user-reportedly-used-morse-code-prompt-to-induce-grok
// - Aug 20, 2025. Brave showed Perplexity Comet following a hidden Reddit comment.
//   The proof stole a Perplexity one-time password. It did not show a bank account being drained.
//   https://brave.com/blog/comet-prompt-injection/
// Reddit and news pass, checked against pages the reader opened:
// - Guardio Labs, Aug 20, 2025. Comet filled a saved card on the lab's fake Walmart and sometimes checked out.
//   https://guard.io/labs/scamlexity-we-put-agentic-ai-browsers-to-the-test-they-clicked-they-paid-they-failed
// - OpenAI Operator system card, Jan 23, 2025. On 100 tasks the unmitigated model ordered the wrong food item.
//   https://openai.com/index/operator-system-card/
// - Anthropic Project Vend, Jun 27, 2025. Claude ran a real office shop, discounted stock, and gave some of it away.
//   https://www.anthropic.com/research/project-vend-1
// Regulator and lab cases checked on the security pass:
// - FCA, May 22, 2024. A Citigroup trader meant to sell $58 million. Controls let $189 billion reach the algorithm, and $1.4 billion of equities sold.
//   https://www.fca.org.uk/news/press-releases/fca-fines-cgml-27-million
// - SEC, October 16, 2013. Knight Capital's router filled 212 customer orders with millions of child orders and lost more than $460 million on August 1, 2012.
//   https://www.sec.gov/newsroom/press-releases/2013-222
// - InjecAgent, March 2024. A fake note told the agent to pay a bill. The paper shows a simulated pay tool being called. No bank was connected.
//   https://arxiv.org/abs/2403.02691
// The Hong Kong deepfake CFO wire was a person sending the money. The software did not. It is not a card case.
//
// Not added: the Hacker News claim of about $78,000 in Codex charges, the $8,000 course post, and the 2017 Alexa dollhouse story.
// The first is an allegation with no invoice. The second is a product post. Snopes could not confirm the third.
//
// A founder's post that 591 unsupervised agents spent thousands of dollars is on a public mirror
// (x.com/nikil/status/2064463565919244308). It is a claim, not an independent audit, so it is not a test.
//
// Illustrations, not reported losses. Do not cite them as incidents:
// - Marquor "confused deputy" $50,000 wire. https://marquor.io/blog-confused-deputy.html
// - datarekha $48,200 invoice page. https://datarekha.com/blog/tool-output-prompt-injection/
// - DEV.to hallucinated wire. https://dev.to/fabsalvadori/your-ai-agent-just-hallucinated-a-wire-transfer-heres-how-i-stopped-it-4e01

import { describe, expect, test } from "bun:test";
import { decide } from "../src/core/decide";
import type { DecisionInput, DecisionState, DeclineCode } from "../src/types";
import { input, signed, state } from "./helpers";

type ExpectCode = "AUTHORIZED" | DeclineCode;

interface Row {
  id: string;
  source: string;
  title: string;
  expect: ExpectCode;
  input?: Partial<DecisionInput>;
  state?: { [K in keyof DecisionState]?: DecisionState[K] | undefined };
  writ?: Parameters<typeof signed>[0];
  dropWrit?: boolean;
}

const raOk = { signatureValid: true as const, nonceFresh: true as const, nonceSeen: false as const };
const eggs = { merchantName: "Mercato", mcc: "5411", amountMinor: 599, purpose: "Find the cheapest delivered eggs" };

const rows: Row[] = [
  // Washington Post Operator eggs. Asked to find cheap eggs. It bought Instacart for $31.43.
  { id: "S01", source: "wapo-2025-02-07", title: "No writ. Operator buys anyway.", expect: "NO_WRIT_FOR_CARD", dropWrit: true, input: { merchantName: "Instacart", mcc: "5411", amountMinor: 3143 } },
  { id: "S02", source: "wapo-2025-02-07", title: "Writ is find eggs at Mercato. Swipe is Instacart.", expect: "MERCHANT_NOT_IN_WRIT", writ: eggs, input: { merchantName: "Instacart", mcc: "5411", amountMinor: 599 } },
  { id: "S03", source: "wapo-2025-02-07", title: "Approved $5.99. Charged $31.43.", expect: "AMOUNT_OVER_WRIT", writ: eggs, input: { merchantName: "Mercato", mcc: "5411", amountMinor: 3143 } },
  { id: "S04", source: "wapo-2025-02-07", title: "Delivery, tip, service and bag fees blow the cap.", expect: "AMOUNT_OVER_WRIT", writ: eggs, input: { merchantName: "Mercato", mcc: "5411", amountMinor: 599 + 799 + 300 + 400 + 25 } },
  { id: "S05", source: "wapo-2025-02-07", title: "Agent reports $19.68. The card posts $31.43.", expect: "AMOUNT_OVER_WRIT", writ: { ...eggs, amountMinor: 1968 }, input: { merchantName: "Mercato", mcc: "5411", amountMinor: 3143 } },
  { id: "S06", source: "wapo-2025-02-07", title: "User walked away. Writ expired before the charge.", expect: "WRIT_EXPIRED", writ: eggs, input: { merchantName: "Mercato", mcc: "5411", amountMinor: 599, now: "2026-11-12T09:00:00.000Z" } },
  { id: "S07", source: "wapo-2025-02-07", title: "Second egg order on a writ already used.", expect: "WRIT_REPLAY", writ: eggs, state: { writStatus: "consumed" }, input: { merchantName: "Mercato", mcc: "5411", amountMinor: 599 } },
  { id: "S08", source: "openai-operator-card", title: "Confirmation safeguard skipped. Signature does not verify.", expect: "WRIT_BAD_SIGNATURE", writ: eggs, state: { writSignatureValid: false }, input: { merchantName: "Mercato", mcc: "5411", amountMinor: 599 } },
  { id: "S09", source: "openai-operator-card", title: "Amount edited after the human signed.", expect: "WRIT_HASH_MISMATCH", writ: eggs, state: { writHashValid: false }, input: { merchantName: "Mercato", mcc: "5411", amountMinor: 599 } },
  { id: "S10", source: "wapo-2025-02-07", title: "Exact approved egg price at the approved shop.", expect: "AUTHORIZED", writ: eggs, input: { merchantName: "Mercato", mcc: "5411", amountMinor: 599 } },
  { id: "S11", source: "wapo-2025-02-07", title: "Instacart padded with trailing underscores still is not Mercato.", expect: "MERCHANT_NOT_IN_WRIT", writ: eggs, input: { merchantName: "Instacart___", mcc: "5411", amountMinor: 599 } },
  { id: "S12", source: "wapo-2025-02-07", title: "Grocery MCC on a software writ.", expect: "MCC_NOT_IN_WRIT", input: { mcc: "5411", amountMinor: 599 } },

  // Reddit r/ChatGPTPro. Agent mode bought coffee on Amazon.
  { id: "S13", source: "reddit-chatgptpro-2025-11-23", title: "Coffee at Amazon. Writ is DataCo.", expect: "MERCHANT_NOT_IN_WRIT", input: { merchantName: "Amazon", amountMinor: 1299 } },
  { id: "S14", source: "reddit-chatgptpro-2025-11-23", title: "Amazon name matches after case fold.", expect: "AUTHORIZED", writ: { merchantName: "amazon", amountMinor: 1299, purpose: "Coffee" }, input: { merchantName: "Amazon", amountMinor: 1299 } },
  { id: "S15", source: "reddit-chatgptpro-2025-11-23", title: "Sponsored lookalike merchant.", expect: "MERCHANT_NOT_IN_WRIT", writ: { merchantName: "Amazon", amountMinor: 1299 }, input: { merchantName: "Amazon Fresh", amountMinor: 1299 } },
  { id: "S16", source: "reddit-chatgptpro-2025-11-23", title: "Low cap of $20. Coffee is $21.", expect: "AMOUNT_OVER_WRIT", writ: { merchantName: "Amazon", amountMinor: 2000, purpose: "Coffee under $20" }, input: { merchantName: "Amazon", amountMinor: 2100 } },
  { id: "S17", source: "reddit-chatgptpro-2025-11-23", title: "User wanted recommendations only. No writ.", expect: "NO_WRIT_FOR_CARD", dropWrit: true, input: { merchantName: "Amazon", amountMinor: 1299 } },

  // Reddit r/ClaudeCode. $25 card, four stores, payment iframe.
  { id: "S18", source: "reddit-claudecode-2026-03-18", title: "$25 card. Charge is $25.01.", expect: "AMOUNT_OVER_WRIT", writ: { amountMinor: 2500, merchantName: "Empik", mcc: "5942", purpose: "A gift under $25" }, input: { amountMinor: 2501, merchantName: "Empik", mcc: "5942" } },
  { id: "S19", source: "reddit-claudecode-2026-03-18", title: "Allegro instead of the approved Empik.", expect: "MERCHANT_NOT_IN_WRIT", writ: { amountMinor: 2500, merchantName: "Empik", mcc: "5942" }, input: { amountMinor: 2500, merchantName: "Allegro", mcc: "5942" } },
  { id: "S20", source: "reddit-claudecode-2026-03-18", title: "Payment processor P24 is not the merchant on the writ.", expect: "MERCHANT_NOT_IN_WRIT", writ: { amountMinor: 2500, merchantName: "Empik", mcc: "5942" }, input: { amountMinor: 2500, merchantName: "P24", mcc: "5942" } },
  { id: "S21", source: "reddit-claudecode-2026-03-18", title: "Keychain read is untrusted after approval.", expect: "TAINTED_RUN", state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:31:00.000Z", source: "Apple Keychain" } } },
  { id: "S22", source: "reddit-claudecode-2026-03-18", title: "Exact $25 at Empik.", expect: "AUTHORIZED", writ: { amountMinor: 2500, merchantName: "Empik", mcc: "5942", purpose: "A gift" }, input: { amountMinor: 2500, merchantName: "Empik", mcc: "5942" } },

  // Reddit r/aiagents. Double buy and spend loops.
  { id: "S23", source: "reddit-aiagents-2026-06-06", title: "Same purchase twice. Writ already consumed.", expect: "WRIT_REPLAY", state: { writStatus: "consumed" } },
  { id: "S24", source: "reddit-aiagents-2026-06-06", title: "Loop holds $330. This $180 does not fit in $500.", expect: "TEAM_POOL_EXHAUSTED", state: { ledger: { team: "research", poolLimitMinor: 50000, reservedMinor: 33000, pendingMinor: 0, settledMinor: 0, releasedMinor: 0, alerts: 0 } } },
  { id: "S25", source: "reddit-aiagents-2026-06-06", title: "Two pending $180 holds. Third $180 exceeds the pool.", expect: "TEAM_POOL_EXHAUSTED", state: { ledger: { team: "research", poolLimitMinor: 50000, reservedMinor: 0, pendingMinor: 36000, settledMinor: 0, releasedMinor: 0, alerts: 0 } } },
  { id: "S26", source: "reddit-aiagents-2026-06-06", title: "Settled spend already $480 of $500.", expect: "TEAM_POOL_EXHAUSTED", input: { amountMinor: 3000 }, writ: { amountMinor: 3000 }, state: { ledger: { team: "research", poolLimitMinor: 50000, reservedMinor: 0, pendingMinor: 0, settledMinor: 48000, releasedMinor: 0, alerts: 0 } } },
  { id: "S27", source: "reddit-aiagents-2026-06-06", title: "Manual approval over $5. This $4.99 writ is inside the cap.", expect: "AUTHORIZED", writ: { amountMinor: 499, purpose: "API credits" }, input: { amountMinor: 499 } },
  { id: "S28", source: "reddit-aiagents-2026-06-06", title: "$5.01 without a matching writ amount.", expect: "AMOUNT_OVER_WRIT", writ: { amountMinor: 500, purpose: "API credits" }, input: { amountMinor: 501 } },
  { id: "S29", source: "reddit-aiagents-2026-06-06", title: "Pool has exactly enough for this swipe.", expect: "AUTHORIZED", state: { ledger: { team: "research", poolLimitMinor: 50000, reservedMinor: 32000, pendingMinor: 0, settledMinor: 0, releasedMinor: 0, alerts: 0 } } },
  { id: "S30", source: "reddit-aiagents-2026-06-06", title: "Released money does not free the pool. Settled still counts.", expect: "TEAM_POOL_EXHAUSTED", state: { ledger: { team: "research", poolLimitMinor: 50000, reservedMinor: 0, pendingMinor: 0, settledMinor: 40000, releasedMinor: 40000, alerts: 0 } } },

  // Reddit r/AutoGPT. Prompt injection, wrong vendor, retries, subscriptions.
  { id: "S31", source: "reddit-autogpt-2026-05-05", title: "Page says buy this. Run is tainted after approval.", expect: "TAINTED_RUN", state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:36:00.000Z", source: "https://vendor.example/paywall" } } },
  { id: "S32", source: "reddit-autogpt-2026-05-05", title: "Injection before approval does not taint this writ.", expect: "AUTHORIZED", state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:00:00.000Z", source: "old page" } } },
  { id: "S33", source: "reddit-autogpt-2026-05-05", title: "Wrong vendor after a poisoned page.", expect: "MERCHANT_NOT_IN_WRIT", input: { merchantName: "NotDataCo" } },
  { id: "S34", source: "reddit-autogpt-2026-05-05", title: "Hidden subscription MCC.", expect: "MCC_NOT_IN_WRIT", input: { mcc: "5968" } },
  { id: "S35", source: "reddit-autogpt-2026-05-05", title: "Retry of a consumed writ.", expect: "WRIT_REPLAY", state: { writStatus: "consumed" } },
  { id: "S36", source: "reddit-autogpt-2026-05-05", title: "Upgraded plan over the approved amount.", expect: "AMOUNT_OVER_WRIT", input: { amountMinor: 18001 } },
  { id: "S37", source: "reddit-autogpt-2026-05-05", title: "Kill switch revoked the writ.", expect: "WRIT_REVOKED", state: { writStatus: "revoked" } },
  { id: "S38", source: "reddit-autogpt-2026-05-05", title: "Daily cap already pending.", expect: "TEAM_POOL_EXHAUSTED", writ: { amountMinor: 500 }, input: { amountMinor: 500 }, state: { ledger: { team: "research", poolLimitMinor: 500, reservedMinor: 0, pendingMinor: 500, settledMinor: 0, releasedMinor: 0, alerts: 0 } } },

  // Reddit r/AI_Agents. Right merchant, wrong booking. Three rooms.
  { id: "S39", source: "reddit-ai-agents-2026-04-20", title: "Right hotel chain, wrong property name.", expect: "MERCHANT_NOT_IN_WRIT", writ: { merchantName: "Hotel Lumen", mcc: "7011", amountMinor: 15000, purpose: "One room" }, input: { merchantName: "Hotel Lumen Airport", mcc: "7011", amountMinor: 15000 } },
  { id: "S40", source: "reddit-ai-agents-2026-04-20", title: "One approved room. Charge is three.", expect: "AMOUNT_OVER_WRIT", writ: { merchantName: "Hotel Lumen", mcc: "7011", amountMinor: 15000 }, input: { merchantName: "Hotel Lumen", mcc: "7011", amountMinor: 45000 } },
  { id: "S41", source: "reddit-ai-agents-2026-04-20", title: "First $50 room fits.", expect: "AUTHORIZED", writ: { merchantName: "Hotel Lumen", mcc: "7011", amountMinor: 5000, id: "writ-room-1", nonce: "room-1" }, input: { merchantName: "Hotel Lumen", mcc: "7011", amountMinor: 5000 } },
  { id: "S42", source: "reddit-ai-agents-2026-04-20", title: "Third $50 room after two are pending.", expect: "TEAM_POOL_EXHAUSTED", writ: { merchantName: "Hotel Lumen", mcc: "7011", amountMinor: 5000, id: "writ-room-3", nonce: "room-3" }, input: { merchantName: "Hotel Lumen", mcc: "7011", amountMinor: 5000 }, state: { ledger: { team: "research", poolLimitMinor: 10000, reservedMinor: 0, pendingMinor: 10000, settledMinor: 0, releasedMinor: 0, alerts: 0 } } },
  { id: "S43", source: "reddit-ai-agents-2026-04-20", title: "Restaurant MCC on a lodging writ.", expect: "MCC_NOT_IN_WRIT", writ: { merchantName: "Hotel Lumen", mcc: "7011", amountMinor: 15000 }, input: { merchantName: "Hotel Lumen", mcc: "5812", amountMinor: 4000 } },

  // Barracuda invoice injection. Infosecurity Magazine.
  { id: "S44", source: "infosecurity-barracuda", title: "Invoice email taints the run.", expect: "TAINTED_RUN", state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:32:00.000Z", source: "invoice email" } } },
  { id: "S45", source: "infosecurity-barracuda", title: "New beneficiary is not the merchant on the writ.", expect: "MERCHANT_NOT_IN_WRIT", input: { merchantName: "Northstar Components" } },
  { id: "S46", source: "infosecurity-barracuda", title: "Changed remittance amount.", expect: "AMOUNT_OVER_WRIT", input: { amountMinor: 4820000 }, writ: { amountMinor: 18000 } },
  { id: "S47", source: "infosecurity-barracuda", title: "Taint at the exact approval time.", expect: "TAINTED_RUN", state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:30:00.000Z", source: "invoice email" } } },
  { id: "S48", source: "infosecurity-barracuda", title: "Currency switched to EUR.", expect: "CURRENCY_NOT_IN_WRIT", input: { currency: "eur" } },

  // Invariant Labs MCP tool poisoning and GitHub issue hijack.
  { id: "S49", source: "invariant-2025-04-01", title: "Poisoned tool description taints the run.", expect: "TAINTED_RUN", state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:40:00.000Z", source: "mcp tool description" } } },
  { id: "S50", source: "invariant-2025-05-26", title: "Public GitHub issue taints the run.", expect: "TAINTED_RUN", state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:40:00.000Z", source: "github issue" } } },
  { id: "S51", source: "invariant-2025-04-01", title: "Taint record is for a different run.", expect: "INTERNAL_ERROR", state: { taint: { runId: "run-other" } } },
  { id: "S52", source: "invariant-2025-04-01", title: "Tool poisoning also swaps the merchant.", expect: "MERCHANT_NOT_IN_WRIT", input: { merchantName: "Attacker Store" } },
  { id: "S53", source: "invariant-2025-05-26", title: "Untrusted issue read before approval. Spend still matches the writ.", expect: "AUTHORIZED", state: { taint: { runId: "run-1", taintedAt: "2026-11-12T07:00:00.000Z", source: "github issue" } } },

  // Ramp and Mercury. Human sets the cap. Agent cannot raise it.
  { id: "S54", source: "ramp-agent-cards", title: "Single-use card. Writ already consumed.", expect: "WRIT_REPLAY", state: { writStatus: "consumed" } },
  { id: "S55", source: "ramp-agent-cards", title: "Hard cap $180. Swipe is $180.", expect: "AUTHORIZED" },
  { id: "S56", source: "ramp-agent-cards", title: "One cent over the hard cap.", expect: "AMOUNT_OVER_WRIT", input: { amountMinor: 18001 } },
  { id: "S57", source: "mercury-agent-cards", title: "Agent cannot raise the team pool. This swipe does not fit.", expect: "TEAM_POOL_EXHAUSTED", state: { ledger: { team: "research", poolLimitMinor: 18000, reservedMinor: 1, pendingMinor: 0, settledMinor: 0, releasedMinor: 0, alerts: 0 } } },
  { id: "S58", source: "mercury-agent-cards", title: "Merchant lock. Other vendor.", expect: "MERCHANT_NOT_IN_WRIT", input: { merchantName: "Other Vendor" } },
  { id: "S59", source: "mercury-agent-cards", title: "Category lock. Ads MCC.", expect: "MCC_NOT_IN_WRIT", input: { mcc: "7311" } },
  { id: "S60", source: "ramp-agent-cards", title: "Card was frozen. Writ revoked.", expect: "WRIT_REVOKED", state: { writStatus: "revoked" } },
  { id: "S61", source: "pymnts-2026-11", title: "Workflow currency is USD. Swipe is GBP.", expect: "CURRENCY_NOT_IN_WRIT", input: { currency: "GBP" } },
  { id: "S62", source: "pymnts-2026-11", title: "Campaign expired.", expect: "WRIT_EXPIRED", input: { now: "2026-11-13T09:00:00.000Z" } },
  { id: "S63", source: "hello-purple-limits", title: "Who sets the limit. A forged signature does not.", expect: "WRIT_BAD_SIGNATURE", state: { writSignatureValid: false } },

  // Payments Dive. Fraud questions, encoded as the checks those questions need.
  { id: "S64", source: "payments-dive", title: "Stolen card number on an agent with no writ.", expect: "NO_WRIT_FOR_CARD", dropWrit: true },
  { id: "S65", source: "payments-dive", title: "Prompt tells the agent to change what it buys.", expect: "TAINTED_RUN", state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:45:00.000Z", source: "injected prompt" } } },
  { id: "S66", source: "payments-dive", title: "Buyer remorse is not a second spend. Writ is consumed.", expect: "WRIT_REPLAY", state: { writStatus: "consumed" } },
  { id: "S67", source: "payments-dive", title: "A burst of charges fills the team pool.", expect: "TEAM_POOL_EXHAUSTED", state: { ledger: { team: "research", poolLimitMinor: 50000, reservedMinor: 20000, pendingMinor: 20000, settledMinor: 10000, releasedMinor: 0, alerts: 0 } } },

  // Remote Authorization request checks. The bank asks. The signature is the first gate.
  { id: "S68", source: "wapo-2025-02-07", title: "RA swipe. Signature missing.", expect: "RA_BAD_SIGNATURE", input: { mode: "ra" } },
  { id: "S69", source: "wapo-2025-02-07", title: "RA swipe. Signature invalid.", expect: "RA_BAD_SIGNATURE", input: { mode: "ra", ra: { signatureValid: false, nonceFresh: true, nonceSeen: false } } },
  { id: "S70", source: "wapo-2025-02-07", title: "RA swipe. Nonce older than 30 seconds.", expect: "RA_STALE_NONCE", input: { mode: "ra", ra: { signatureValid: true, nonceFresh: false, nonceSeen: false } } },
  { id: "S71", source: "reddit-aiagents-2026-06-06", title: "RA swipe. Same nonce twice.", expect: "RA_NONCE_REPLAY", input: { mode: "ra", ra: { signatureValid: true, nonceFresh: true, nonceSeen: true } } },
  { id: "S72", source: "wapo-2025-02-07", title: "RA swipe. Signature good, merchant wrong.", expect: "MERCHANT_NOT_IN_WRIT", input: { mode: "ra", ra: raOk, merchantName: "Instacart" } },
  { id: "S73", source: "wapo-2025-02-07", title: "RA swipe. Signature good, amount over.", expect: "AMOUNT_OVER_WRIT", writ: eggs, input: { mode: "ra", ra: raOk, merchantName: "Mercato", mcc: "5411", amountMinor: 3143 } },
  { id: "S74", source: "invariant-2025-05-26", title: "RA swipe. Signature good, run tainted.", expect: "TAINTED_RUN", input: { mode: "ra", ra: raOk }, state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:50:00.000Z", source: "github issue" } } },
  { id: "S75", source: "ramp-agent-cards", title: "RA swipe. Everything matches.", expect: "AUTHORIZED", input: { mode: "ra", ra: raOk } },
  { id: "S76", source: "openai-operator-card", title: "Bad signature wins over a bad merchant.", expect: "RA_BAD_SIGNATURE", input: { mode: "ra", ra: { signatureValid: false, nonceFresh: true, nonceSeen: false }, merchantName: "Instacart" } },
  { id: "S77", source: "openai-operator-card", title: "Stale nonce wins over a tainted run.", expect: "RA_STALE_NONCE", input: { mode: "ra", ra: { signatureValid: true, nonceFresh: false, nonceSeen: false } }, state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:50:00.000Z", source: "page" } } },

  // Ledger and reserve. The company cash, not the card limit.
  { id: "S78", source: "mercury-agent-cards", title: "Ledger hash chain failed.", expect: "STATE_UNVERIFIED", state: { chainVerified: false } },
  { id: "S79", source: "mercury-agent-cards", title: "Chain failure wins over a bad signature.", expect: "STATE_UNVERIFIED", state: { chainVerified: false, writSignatureValid: false } },
  { id: "S80", source: "mercury-agent-cards", title: "No live balance.", expect: "UPSTREAM_ERROR", state: { reserve: undefined } },
  { id: "S81", source: "mercury-agent-cards", title: "Balance older than 60 seconds.", expect: "BALANCE_STALE", state: { reserve: { liveBalanceMinor: 1_000_000_000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 0, asOf: "2026-11-12T08:33:00.000Z", maxAgeMs: 60_000 } } },
  { id: "S82", source: "mercury-agent-cards", title: "Balance is 30 seconds old.", expect: "AUTHORIZED", state: { reserve: { liveBalanceMinor: 1_000_000_000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 0, asOf: "2026-11-12T08:34:30.000Z", maxAgeMs: 60_000 } } },
  { id: "S83", source: "mercury-agent-cards", title: "Reserve would fall under the floor.", expect: "RESERVE_FLOOR", state: { reserve: { liveBalanceMinor: 2_500_000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 490_000 } } },
  { id: "S84", source: "mercury-agent-cards", title: "Ring fence is tighter than the bank balance.", expect: "RESERVE_FLOOR", state: { reserve: { liveBalanceMinor: 9_000_000, ringFenceMinor: 2_010_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 0 } } },
  { id: "S85", source: "mercury-agent-cards", title: "Other open reservations already use the cushion.", expect: "RESERVE_FLOOR", input: { amountMinor: 100 }, writ: { amountMinor: 100 }, state: { reserve: { liveBalanceMinor: 2_500_000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 499_950 } } },
  { id: "S86", source: "mercury-agent-cards", title: "Pool check wins before a stale balance.", expect: "TEAM_POOL_EXHAUSTED", state: { ledger: { team: "research", poolLimitMinor: 1000, reservedMinor: 0, pendingMinor: 0, settledMinor: 0, releasedMinor: 0, alerts: 0 }, reserve: { liveBalanceMinor: 1_000_000_000, ringFenceMinor: 2_500_000, reserveFloorMinor: 2_000_000, openReservationsMinor: 0, asOf: "2026-11-12T08:00:00.000Z" } }, writ: { amountMinor: 1001 }, input: { amountMinor: 1001 } },
  { id: "S87", source: "mercury-agent-cards", title: "Team row is for a different team.", expect: "INTERNAL_ERROR", state: { ledger: { team: "other", poolLimitMinor: 50000, reservedMinor: 0, pendingMinor: 0, settledMinor: 0, releasedMinor: 0, alerts: 0 } } },

  // Writ lifecycle and match edges.
  { id: "S88", source: "ramp-agent-cards", title: "Status missing.", expect: "INTERNAL_ERROR", state: { writStatus: undefined } },
  { id: "S89", source: "ramp-agent-cards", title: "Armed writ can still authorize once.", expect: "AUTHORIZED", state: { writStatus: "armed" } },
  { id: "S90", source: "ramp-agent-cards", title: "Status says expired.", expect: "WRIT_EXPIRED", state: { writStatus: "expired" } },
  { id: "S91", source: "wapo-2025-02-07", title: "Merchant case and surrounding spaces match.", expect: "AUTHORIZED", input: { merchantName: "  dataCo  " } },
  { id: "S92", source: "wapo-2025-02-07", title: "Trailing underscores match DataCo.", expect: "AUTHORIZED", input: { merchantName: "DataCo___" } },
  { id: "S93", source: "wapo-2025-02-07", title: "Amount one cent under the writ.", expect: "AUTHORIZED", input: { amountMinor: 17999 } },
  { id: "S94", source: "wapo-2025-02-07", title: "Zero cents is not a swipe.", expect: "INTERNAL_ERROR", input: { amountMinor: 0 } },
  { id: "S95", source: "wapo-2025-02-07", title: "Negative cents.", expect: "INTERNAL_ERROR", input: { amountMinor: -1 } },
  { id: "S96", source: "wapo-2025-02-07", title: "Clock value is not a time.", expect: "INTERNAL_ERROR", input: { now: "not-a-time" } },
  { id: "S97", source: "infosecurity-barracuda", title: "Whitespace currency still matches USD.", expect: "AUTHORIZED", input: { currency: " usd " } },
  { id: "S98", source: "infosecurity-barracuda", title: "A nearby MCC is not 5734.", expect: "MCC_NOT_IN_WRIT", input: { mcc: "5735" } },
  { id: "S99", source: "reddit-autogpt-2026-05-05", title: "Unreadable taint time fails closed.", expect: "TAINTED_RUN", state: { taint: { runId: "run-1", taintedAt: "yesterday", source: "page" } } },
  { id: "S100", source: "wapo-2025-02-07", title: "The approved task, the approved shop, the approved amount.", expect: "AUTHORIZED" },
];

function decideRow(row: Row) {
  const writ = signed(row.writ);
  const base = state(writ, (row.state ?? {}) as Partial<DecisionState>);
  if (row.dropWrit) delete (base as { writ?: unknown }).writ;
  return decide(input(row.input), base);
}

const checkedLater: Row[] = [
  { id: "X01", source: "bankr-grok-2026-05-04", title: "Untrusted reply tells the agent to pay a new address.", expect: "TAINTED_RUN", state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:49:00.000Z", source: "morse code reply" } } },
  { id: "X02", source: "bankr-grok-2026-05-04", title: "No writ for the address that received the tokens.", expect: "NO_WRIT_FOR_CARD", dropWrit: true, input: { merchantName: "ilhamrafli.base.eth", amountMinor: 15_000_000 } },
  { id: "X03", source: "brave-comet-2025-08-20", title: "Hidden Reddit comment taints the run before a spend.", expect: "TAINTED_RUN", state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:49:00.000Z", source: "reddit comment" } } },
  { id: "R01", source: "guardio-comet-2025-08-20", title: "Fake store page taints the run.", expect: "TAINTED_RUN", state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:49:00.000Z", source: "fake walmart page" } } },
  { id: "R02", source: "guardio-comet-2025-08-20", title: "Saved card is used at a store that is not on the writ.", expect: "MERCHANT_NOT_IN_WRIT", input: { merchantName: "Walmart" } },
  { id: "R03", source: "openai-operator-card", title: "The food that arrived is not the food on the writ.", expect: "MERCHANT_NOT_IN_WRIT", writ: { merchantName: "Mercato", mcc: "5411", amountMinor: 599, purpose: "Eggs" }, input: { merchantName: "Instacart", mcc: "5411", amountMinor: 599 } },
  { id: "R04", source: "anthropic-project-vend-2025-06-27", title: "A discount code the shop did not approve.", expect: "WRIT_BAD_SIGNATURE", state: { writSignatureValid: false } },
  { id: "C01", source: "fca-citi-2024-05-22", title: "The order that left was far above the size the trader entered.", expect: "AMOUNT_OVER_WRIT", writ: { amountMinor: 5_800_000, merchantName: "European equities", mcc: "6211", purpose: "Sell the basket" }, input: { amountMinor: 140_000_000, merchantName: "European equities", mcc: "6211" } },
  { id: "C02", source: "sec-knight-2013-10-16", title: "Child orders fill the book past the team's limit.", expect: "TEAM_POOL_EXHAUSTED", state: { ledger: { team: "research", poolLimitMinor: 50000, reservedMinor: 0, pendingMinor: 50000, settledMinor: 0, releasedMinor: 0, alerts: 1 } } },
  { id: "C03", source: "injecagent-2024-03", title: "A note in the tool result says to pay a bill.", expect: "TAINTED_RUN", state: { taint: { runId: "run-1", taintedAt: "2026-11-12T08:49:00.000Z", source: "evernote note" } } },
];

describe("scenario world", () => {
  test("there are 100 sourced scenarios and the ids are unique", () => {
    expect(rows).toHaveLength(100);
    expect(new Set(rows.map((r) => r.id)).size).toBe(100);
  });

  for (const row of rows) {
    test(`${row.id} ${row.title}`, () => {
      const decision = decideRow(row);
      if (row.expect === "AUTHORIZED") {
        expect(decision.status).toBe("AUTHORIZED");
        return;
      }
      expect(decision.status).toBe("DECLINED");
      if (decision.status === "DECLINED") expect(decision.code).toBe(row.expect as DeclineCode);
    });
  }
});

describe("scenario world, checked after the X pass", () => {
  for (const row of checkedLater) {
    test(`${row.id} ${row.title}`, () => {
      const decision = decideRow(row);
      expect(decision.status).toBe("DECLINED");
      if (decision.status === "DECLINED") expect(decision.code).toBe(row.expect as DeclineCode);
    });
  }
});
