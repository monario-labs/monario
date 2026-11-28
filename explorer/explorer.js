"use strict";

const height = document.querySelector("#height");
const status = document.querySelector("#status");
const results = document.querySelector("#blocks");
const empty = document.querySelector("#empty");
const query = document.querySelector("#query");
const hash = /^[0-9a-f]{64}$/;
const number = /^(0|[1-9][0-9]{0,19})$/;
const refreshInterval = 30_000;
let latest;

function coinAmount(atoms) {
  const value = BigInt(atoms);
  const whole = value / 100_000_000n;
  const fraction = (value % 100_000_000n).toString().padStart(8, "0").replace(/0+$/, "");
  return whole.toLocaleString() + (fraction ? "." + fraction : "") + " MONAR";
}

function transactionList(block) {
  const section = document.createElement("div");
  section.className = "transactions";
  const title = document.createElement("h3");
  title.textContent = block.transaction_count + (block.transaction_count === 1 ? " transaction" : " transactions");
  section.append(title);
  const list = document.createElement("ul");
  block.transaction_ids.forEach((id, index) => {
    const item = document.createElement("li");
    const label = document.createElement("strong");
    label.textContent = index === 0 ? "Coinbase" : "Transaction";
    const digest = document.createElement("code");
    digest.textContent = id;
    item.append(label, digest);
    if (index === 0) {
      for (const output of block.coinbase_outputs) {
        const payment = document.createElement("div");
        payment.className = "payment";
        const amount = document.createElement("span");
        const recipient = document.createElement("code");
        amount.textContent = coinAmount(output.atoms);
        recipient.textContent = output.address ?? "Nonstandard transparent output";
        payment.append(amount, recipient);
        item.append(payment);
      }
      if (block.coinbase_output_count > block.coinbase_outputs.length) {
        const note = document.createElement("p");
        note.textContent = "Showing the first eight transparent coinbase outputs.";
        item.append(note);
      }
    }
    list.append(item);
  });
  section.append(list);
  if (block.transaction_count > block.transaction_ids.length) {
    const note = document.createElement("p");
    note.textContent = "Showing the first 24 transactions in block order.";
    section.append(note);
  }
  return section;
}

function render() {
  if (!latest) return;
  const filter = query.value.trim().toLowerCase();
  const opened = new Set([...results.querySelectorAll("details[open]")].map(item => item.dataset.hash));
  const visible = latest.blocks.filter(block => block.height === filter || block.id.startsWith(filter) ||
    block.transaction_ids?.some(id => id.startsWith(filter)));
  results.replaceChildren(...visible.map(block => {
    const row = document.createElement("li");
    const details = document.createElement("details");
    details.dataset.hash = block.id;
    details.open = opened.has(block.id) || Boolean(filter && block.transaction_ids?.some(id => id.startsWith(filter)));
    const title = document.createElement("summary");
    const label = document.createElement("strong");
    label.textContent = "#" + block.height;
    const id = document.createElement("code");
    id.textContent = block.id;
    title.append(label, id);
    const fields = document.createElement("dl");
    for (const [name, value] of [["Block hash", block.id], ["Parent", block.parent], ["Commitment", block.commitment]]) {
      const term = document.createElement("dt");
      const description = document.createElement("dd");
      const formatted = document.createElement("code");
      term.textContent = name;
      formatted.textContent = value;
      description.append(formatted);
      fields.append(term, description);
    }
    details.append(title, fields);
    if (block.transaction_ids) details.append(transactionList(block));
    row.append(details);
    return row;
  }));
  empty.hidden = visible.length > 0;
  empty.textContent = filter ? "No matching recent block." : "No mined blocks yet.";
}

async function refresh() {
  try {
    const response = await fetch("snapshot.json", {cache: "no-store", signal: AbortSignal.timeout(5000)});
    if (!response.ok) throw new Error("Snapshot unavailable");
    const data = await response.json();
    if (data?.network !== "testnet" || !number.test(data.height) || !hash.test(data.tip) ||
        !Array.isArray(data.blocks) || data.blocks.length > 24 ||
        !data.blocks.every(block => block && typeof block.height === "string" && number.test(block.height) &&
          [block.id, block.parent, block.commitment].every(isHash) &&
          (data.version === 2 ? validTransactions(block) : block.transaction_ids === undefined))) {
      throw new Error("Invalid snapshot");
    }
    const generated = new Date(data.generated_at);
    if (!Number.isFinite(generated.getTime())) throw new Error("Invalid snapshot date");
    const changed = latest?.tip !== data.tip || latest?.version !== data.version;
    latest = data;
    height.textContent = BigInt(data.height).toLocaleString();
    const age = Date.now() - generated.getTime();
    status.textContent = (age >= 120_000 ? "Showing an earlier snapshot. " : "") +
      "Last checked " + generated.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit", timeZoneName: "short"});
    if (changed) render();
  } catch {
    status.textContent = latest ? "Refresh unavailable. Showing the last snapshot." : "Chain data is temporarily unavailable.";
  } finally {
    window.setTimeout(refresh, refreshInterval);
  }
}

function isHash(value) {
  return typeof value === "string" && hash.test(value);
}

function validTransactions(block) {
  return Number.isSafeInteger(block.transaction_count) && block.transaction_count >= 1 &&
    Array.isArray(block.transaction_ids) && block.transaction_ids.length === Math.min(24, block.transaction_count) &&
    block.transaction_ids.every(isHash) &&
    Number.isSafeInteger(block.coinbase_output_count) && block.coinbase_output_count >= 0 &&
    Array.isArray(block.coinbase_outputs) && block.coinbase_outputs.length === Math.min(8, block.coinbase_output_count) &&
    block.coinbase_outputs.every(output => output && typeof output.atoms === "string" && number.test(output.atoms) &&
      (output.address === null || (typeof output.address === "string" && /^testmont1[023456789acdefghjklmnpqrstuvwxyz]{40,60}$/.test(output.address))));
}

document.querySelector("#search").addEventListener("submit", event => event.preventDefault());
query.addEventListener("input", render);
refresh();
