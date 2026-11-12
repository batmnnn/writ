const eventList = document.getElementById("event-list");
const poolLabel = document.getElementById("pool-label");
const poolSettled = document.getElementById("pool-settled");
const poolPending = document.getElementById("pool-pending");
const poolReserved = document.getElementById("pool-reserved");
const poolLegend = document.getElementById("pool-legend");
const reserveLabel = document.getElementById("reserve-label");
const reserveFill = document.getElementById("reserve-fill");
const reserveMark = document.getElementById("reserve-floor-mark");
const reserveNote = document.getElementById("reserve-note");
const approvalFields = document.getElementById("approval-fields");
const finalBody = document.getElementById("final-body");

function money(n) {
  if (!Number.isInteger(n)) return "$?";
  const sign = n < 0 ? "-" : "";
  const abs = Math.abs(n);
  const dollars = Math.floor(abs / 100).toLocaleString("en-US");
  const cents = abs % 100;
  return cents === 0 ? sign + "$" + dollars : sign + "$" + dollars + "." + String(cents).padStart(2, "0");
}

function ist(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const fmt = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Asia/Kolkata",
    weekday: "short",
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
  return fmt.format(d) + " IST";
}

function pct(part, whole) {
  if (!whole || whole <= 0) return 0;
  return Math.max(0, Math.min(100, (part / whole) * 100));
}

function resetUi() {
  eventList.replaceChildren();
  poolLabel.textContent = "Waiting for the demo.";
  poolSettled.style.width = "0";
  poolPending.style.width = "0";
  poolReserved.style.width = "0";
  poolLegend.replaceChildren();
  reserveLabel.textContent = "Waiting for the demo.";
  reserveFill.style.width = "0";
  reserveFill.classList.remove("low");
  reserveMark.style.left = "0";
  reserveNote.textContent = "";
  approvalFields.innerHTML = "<dt>Status</dt><dd>No writ yet.</dd>";
  finalBody.innerHTML = '<tr><td colspan="6" class="muted">Run in progress.</td></tr>';
}

function addEvent(tone, title, body, at) {
  const li = document.createElement("li");
  const when = document.createElement("span");
  when.className = "when";
  when.textContent = ist(at);
  const line = document.createElement("div");
  line.className = tone;
  line.textContent = title;
  li.append(when, line);
  if (body) {
    const extra = document.createElement("div");
    extra.textContent = body;
    li.append(extra);
  }
  eventList.append(li);
  eventList.parentElement.scrollTop = eventList.parentElement.scrollHeight;
}

function renderPool(e) {
  const used = e.reservedMinor + e.pendingMinor + e.settledMinor;
  const free = Math.max(0, e.poolLimitMinor - used);
  poolLabel.textContent = e.team + " pool: " + money(used) + " of " + money(e.poolLimitMinor) + " used.";
  poolSettled.style.width = pct(e.settledMinor, e.poolLimitMinor) + "%";
  poolPending.style.width = pct(e.pendingMinor, e.poolLimitMinor) + "%";
  poolReserved.style.width = pct(e.reservedMinor, e.poolLimitMinor) + "%";
  poolLegend.innerHTML =
    '<li><span class="dot settled"></span>Settled ' +
    money(e.settledMinor) +
    '</li><li><span class="dot pending"></span>Pending ' +
    money(e.pendingMinor) +
    '</li><li><span class="dot reserved"></span>Reserved ' +
    money(e.reservedMinor) +
    '</li><li><span class="dot free"></span>Free ' +
    money(free) +
    "</li>";
}

function renderReserve(e) {
  const cap = e.ringFenceMinor;
  const usable = Math.min(e.liveBalanceMinor, e.ringFenceMinor) - e.openReservationsMinor;
  reserveLabel.textContent =
    "Live " +
    money(e.liveBalanceMinor) +
    ", ring fence " +
    money(e.ringFenceMinor) +
    ", floor " +
    money(e.reserveFloorMinor) +
    ".";
  reserveFill.style.width = pct(Math.max(0, usable), cap) + "%";
  reserveFill.classList.toggle("low", usable < e.reserveFloorMinor);
  reserveMark.style.left = pct(e.reserveFloorMinor, cap) + "%";
  reserveNote.textContent = e.simulated
    ? "Simulated supplier bill. The wallet was not moved."
    : "Open reservations " + money(e.openReservationsMinor) + ".";
}

function renderApproval(a) {
  const sig = a.signatureValid
    ? '<span class="sig-ok">Signature valid</span>'
    : '<span class="sig-no">Signature not valid</span>';
  approvalFields.innerHTML =
    "<dt>Agent</dt><dd>" +
    escapeHtml(a.agent) +
    " / " +
    escapeHtml(a.team) +
    "</dd>" +
    "<dt>Purpose</dt><dd>" +
    escapeHtml(a.purpose) +
    "</dd>" +
    "<dt>Merchant</dt><dd>" +
    escapeHtml(a.merchantName) +
    ", MCC " +
    escapeHtml(a.mcc) +
    "</dd>" +
    "<dt>Amount</dt><dd>" +
    money(a.amountMinor) +
    " " +
    escapeHtml(a.currency) +
    "</dd>" +
    "<dt>Approved</dt><dd>" +
    escapeHtml(a.approvedBy) +
    " at " +
    ist(a.approvedAt) +
    "</dd>" +
    "<dt>Expires</dt><dd>" +
    ist(a.expiresAt) +
    "</dd>" +
    '<dt>Hash</dt><dd class="hash">' +
    escapeHtml(a.hash) +
    "</dd>" +
    "<dt>Signature</dt><dd>" +
    sig +
    "</dd>";
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function renderFinal(e) {
  if (!e.rows.length) {
    finalBody.innerHTML = '<tr><td colspan="6" class="muted">No rows.</td></tr>';
    return;
  }
  finalBody.replaceChildren();
  for (const row of e.rows) {
    const tr = document.createElement("tr");
    const tone = row.result === "AUTHORIZED" ? "ok" : "no";
    tr.innerHTML =
      "<td>" +
      escapeHtml(row.scene) +
      "</td><td>" +
      escapeHtml(row.agent) +
      "</td><td>" +
      escapeHtml(row.task) +
      "</td><td>" +
      escapeHtml(row.amount) +
      '</td><td class="' +
      tone +
      '">' +
      escapeHtml(row.result) +
      "</td><td>" +
      escapeHtml(row.reason) +
      "</td>";
    finalBody.append(tr);
  }
}

function apply(e) {
  switch (e.kind) {
    case "reset":
      resetUi();
      addEvent("", e.replay ? "Replay start (FakeAdapter, no Airwallex keys)." : "Live start. Frozen card.", "", e.at);
      break;
    case "log":
      addEvent("", e.scene + ": " + e.text, "", e.at);
      break;
    case "decision": {
      const tone = e.status === "AUTHORIZED" ? "ok" : "no";
      addEvent(tone, e.scene + ": " + e.code, e.reason, e.at);
      break;
    }
    case "approval":
      renderApproval(e.approval);
      addEvent("", e.scene + ": writ hashed " + e.approval.hash.slice(0, 12), "", e.at);
      break;
    case "pool":
      renderPool(e);
      break;
    case "reserve":
      renderReserve(e);
      break;
    case "taint":
      addEvent("warn", "Taint: agent read " + e.source, "Card freezes. Later swipes are refused.", e.at);
      break;
    case "swipe": {
      const tone = e.accepted ? "ok" : "no";
      const card = e.cardLast4 ? " card …" + e.cardLast4 : "";
      addEvent(tone, e.scene + ": swipe " + (e.accepted ? "accepted" : "refused") + card, e.reason, e.at);
      break;
    }
    case "final":
      renderFinal(e);
      break;
    case "done":
      addEvent(e.ok ? "ok" : "no", e.ok ? "Demo finished." : "Demo failed.", "", e.at);
      break;
  }
}

const src = new EventSource("/events");
src.addEventListener("writ", (ev) => {
  try {
    apply(JSON.parse(ev.data));
  } catch {
    /* ignore a bad frame */
  }
});
