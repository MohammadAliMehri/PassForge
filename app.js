/* ============================================================
   PassForge — app.js
   100% local: no network calls, no storage, no console logging
   of passwords. Generation uses crypto.getRandomValues().
   ============================================================ */

"use strict";

/* ---------------- Common password list (small local sample) ---------------- */

const COMMON_PASSWORDS = new Set([
  "123456", "password", "123456789", "12345678", "12345", "qwerty",
  "1234567", "111111", "1234567890", "123123", "abc123", "password1",
  "qwerty123", "admin", "letmein", "welcome", "monkey", "dragon",
  "login", "princess", "football", "iloveyou", "sunshine", "master",
  "hello", "freedom", "whatever", "qazwsx", "trustno1", "batman",
  "passw0rd", "zaq12wsx", "superman", "starwars", "michael", "ninja",
  "mustang", "shadow", "ashley", "bailey", "baseball", "flower",
  "hottie", "loveme", "snoopy", "summer", "winter", "soccer",
]);

/* Sequential keyboard rows and alphabet runs used for sequence detection */
const SEQUENCE_PATTERNS = [
  "abcdefghijklmnopqrstuvwxyz",
  "0123456789",
  "qwertyuiop",
  "asdfghjkl",
  "zxcvbnm",
];

/* ---------------- DOM references ---------------- */

const els = {
  analyzerCard: document.getElementById("analyzer"),
  input: document.getElementById("password-input"),
  toggleVisibility: document.getElementById("toggle-visibility"),
  eyeOpen: document.querySelector("#toggle-visibility .eye-open"),
  eyeClosed: document.querySelector("#toggle-visibility .eye-closed"),
  clear: document.getElementById("clear-password"),

  strengthLabel: document.getElementById("strength-label"),
  strengthScore: document.getElementById("strength-score"),
  meterFill: document.getElementById("strength-meter-fill"),
  meterTrack: document.getElementById("strength-meter-track"),

  statLength: document.getElementById("stat-length"),
  statEntropy: document.getElementById("stat-entropy"),
  statClasses: document.getElementById("stat-classes"),

  checklist: {
    length: document.getElementById("check-length"),
    lower: document.getElementById("check-lower"),
    upper: document.getElementById("check-upper"),
    number: document.getElementById("check-number"),
    symbol: document.getElementById("check-symbol"),
    common: document.getElementById("check-common"),
    seq: document.getElementById("check-seq"),
    repeat: document.getElementById("check-repeat"),
  },

  feedbackList: document.getElementById("feedback-list"),

  output: document.getElementById("generated-output"),
  generateBtn: document.getElementById("generate-btn"),
  regenerateBtn: document.getElementById("regenerate-btn"),
  usePasswordBtn: document.getElementById("use-password-btn"),
  copyBtn: document.getElementById("copy-password"),
  copyStatus: document.getElementById("copy-status"),
  generatorError: document.getElementById("generator-error"),

  lengthSlider: document.getElementById("length-slider"),
  lengthValue: document.getElementById("length-value"),
  optLower: document.getElementById("opt-lower"),
  optUpper: document.getElementById("opt-upper"),
  optNumber: document.getElementById("opt-number"),
  optSymbol: document.getElementById("opt-symbol"),
  optExcludeAmbiguous: document.getElementById("opt-exclude-ambiguous"),

  toast: document.getElementById("toast"),
};

/* ---------------- Strength bands ---------------- */

/* Colors as hex: some engines don't resolve var() inside inline styles. */
const BANDS = [
  { min: 80, label: "Excellent", color: "#16a34a" },
  { min: 60, label: "Strong",     color: "#4ade80" },
  { min: 40, label: "Good",       color: "#eab308" },
  { min: 20, label: "Fair",       color: "#f97316" },
  { min: 1,  label: "Weak",       color: "#ef4444" },
  { min: 0,  label: "Very Weak",  color: "#ef4444" },
];

/* ============================================================
   ANALYSIS
   ============================================================ */

/** Character-class counts and composition flags for a password. */
function analyzeComposition(pw) {
  return {
    length: pw.length,
    hasLower: /[a-z]/.test(pw),
    hasUpper: /[A-Z]/.test(pw),
    hasNumber: /\d/.test(pw),
    hasSymbol: /[^a-zA-Z0-9\s]/.test(pw),
  };
}

/** True if the password (case-insensitive, leet-normalized) is a known common password. */
function isCommonPassword(pw) {
  const lower = pw.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) return true;

  const normalized = lower
    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")
    .replace(/@/g, "a")
    .replace(/\$/g, "s");
  if (COMMON_PASSWORDS.has(normalized)) return true;

  // Also catch "password1", "admin123" style variants of very weak bases.
  const bases = ["password", "admin", "letmein", "welcome", "qwerty"];
  const startsWithBase = (form) => bases.some((b) => form.startsWith(b) && form.length <= b.length + 4);
  return startsWithBase(lower) || startsWithBase(normalized);
}

/** True if the password contains a run of 3+ sequential characters (either direction). */
function hasSequentialChars(pw) {
  const lower = pw.toLowerCase();
  for (const seq of SEQUENCE_PATTERNS) {
    const rev = [...seq].reverse().join("");
    for (const s of [seq, rev]) {
      for (let i = 0; i <= s.length - 3; i++) {
        if (lower.includes(s.slice(i, i + 3))) return true;
      }
    }
  }
  return false;
}

/** True if any character repeats 3+ times in a row (e.g. "aaa", "111"). */
function hasRepeatedChars(pw) {
  return /(.)\1{2,}/.test(pw);
}

/**
 * Estimate entropy in bits.
 * For passwords without detected patterns this uses the classic charset^length
 * formula; pattern-heavy passwords are penalized toward the effective pool size.
 */
function estimateEntropyBits(pw) {
  if (!pw) return 0;

  let pool = 0;
  if (/[a-z]/.test(pw)) pool += 26;
  if (/[A-Z]/.test(pw)) pool += 26;
  if (/\d/.test(pw)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;

  let bits = pw.length * Math.log2(pool || 1);

  // Penalize structure that shrinks the effective search space.
  let penalty = 0;
  if (isCommonPassword(pw)) penalty += Math.min(bits * 0.9, 40); // dictionary words ≈ near-zero entropy
  if (hasSequentialChars(pw)) penalty += 8;
  if (hasRepeatedChars(pw)) penalty += 6;
  const uniqueRatio = new Set(pw).size / pw.length;
  if (uniqueRatio < 0.5) penalty += (0.5 - uniqueRatio) * 30;

  return Math.max(0, Math.round(bits - penalty));
}

/**
 * Score a password from 0–100 by blending length and measured entropy,
 * then applying penalties for weak patterns.
 */
function scorePassword(pw) {
  if (!pw) return { score: 0, feedback: [] };

  const c = analyzeComposition(pw);
  const classCount = [c.hasLower, c.hasUpper, c.hasNumber, c.hasSymbol].filter(Boolean).length;

  // Entropy component (0–70): ~100 bits maps to the full 70.
  const entropy = estimateEntropyBits(pw);
  let score = Math.min(70, (entropy / 100) * 70);

  // Length component (0–30): grows to 30 at 18+ chars.
  score += Math.min(30, (c.length / 18) * 30);

  const feedback = [];

  // Hard penalties
  if (isCommonPassword(pw)) {
    score -= 35;
    feedback.push("Avoid common passwords — they are cracked instantly.");
  }

  // Composition rules → feedback messages
  if (c.length < 8) {
    score -= 20;
    feedback.push("This password is far too short.");
  } else if (c.length < 12) {
    feedback.push("Use at least 12 characters.");
  }

  if (!c.hasLower && (c.hasUpper || c.hasNumber)) feedback.push("Add lowercase letters.");
  else if (!c.hasUpper && (c.hasLower || c.hasNumber || c.hasSymbol)) feedback.push("Add uppercase letters.");

  if (!c.hasNumber && (c.hasLower || c.hasUpper)) feedback.push("Add numbers.");
  if (!c.hasSymbol && c.length > 0) feedback.push("Add symbols (e.g. ! @ # %).");

  if (classCount === 1) {
    if (c.hasNumber) feedback.push("Only numbers — add letters and symbols.");
    else feedback.push("Only letters — mix in numbers and symbols.");
    score -= 10;
  }

  if (classCount >= 3 && c.length >= 16) score += 6;

  if (hasRepeatedChars(pw)) {
    score -= 10;
    feedback.push("Avoid repeated characters (like \"aaa\" or \"111\").");
  }
  if (hasSequentialChars(pw)) {
    score -= 10;
    feedback.push("Avoid sequential characters (like \"abc\", \"123\", \"qwerty\").");
  }
  if (uniqueRatioOf(pw) < 0.4 && c.length >= 6) {
    feedback.push("Use more unique characters.");
  }

  return { score: clampScore(score), feedback };
}

function uniqueRatioOf(pw) {
  return pw ? new Set(pw).size / pw.length : 1;
}

function clampScore(n) {
  return Math.max(0, Math.min(100, Math.round(n)));
}

/* ---------------- Checklist state ---------------- */

const CHECK_KEYS = ["length", "lower", "upper", "number", "symbol", "common", "seq", "repeat"];

/** Set each checklist item to pass / fail / neutral. */
function updateChecklist(pw, c) {
  const states = {
    length: pw ? (c.length >= 12 ? "pass" : "fail") : "neutral",
    lower: pw ? (c.hasLower ? "pass" : "fail") : "neutral",
    upper: pw ? (c.hasUpper ? "pass" : "fail") : "neutral",
    number: pw ? (c.hasNumber ? "pass" : "fail") : "neutral",
    symbol: pw ? (c.hasSymbol ? "pass" : "fail") : "neutral",
    common: pw ? (!isCommonPassword(pw) ? "pass" : "fail") : "neutral",
    seq: pw ? (!hasSequentialChars(pw) ? "pass" : "fail") : "neutral",
    repeat: pw ? (!hasRepeatedChars(pw) ? "pass" : "fail") : "neutral",
  };
  for (const key of CHECK_KEYS) {
    els.checklist[key].dataset.state = states[key];
  }
}

/* ---------------- Meter rendering ---------------- */

function bandForScore(score) {
  return BANDS.find((b) => score >= b.min) || BANDS[BANDS.length - 1];
}

function renderStrength(pw) {
  const { score, feedback } = scorePassword(pw);
  const isEmpty = pw.length === 0;
  const band = bandForScore(score);

  const shownScore = isEmpty ? 0 : score;
  // Keep a thin sliver visible so even a 0/100 password shows its band color.
  const shownWidth = isEmpty ? 0 : Math.max(3, score);

  els.meterFill.style.width = `${shownWidth}%`;
  els.meterFill.style.backgroundColor = isEmpty ? "transparent" : band.color;

  // Re-trigger pulse animation on change
  els.meterFill.classList.remove("pulse");
  void els.meterFill.offsetWidth; // force reflow so the animation restarts
  els.meterFill.classList.add("pulse");

  els.strengthLabel.textContent = isEmpty ? "Waiting for input…" : band.label;
  els.strengthLabel.style.color = isEmpty ? "" : band.color;
  els.strengthScore.textContent = `${shownScore} / 100`;
  els.meterTrack.setAttribute("aria-valuenow", String(shownScore));

  const c = analyzeComposition(pw);
  els.statLength.textContent = String(c.length);
  els.statEntropy.textContent = String(isEmpty ? 0 : estimateEntropyBits(pw));
  els.statClasses.textContent = `${
    [c.hasLower, c.hasUpper, c.hasNumber, c.hasSymbol].filter(Boolean).length
  } / 4`;

  updateChecklist(pw, c);

  // Feedback list
  els.feedbackList.textContent = "";
  if (isEmpty) return;
  if (feedback.length === 0) {
    const li = document.createElement("li");
    li.className = "feedback-empty";
    li.textContent = "✓ Great password — no suggestions.";
    els.feedbackList.appendChild(li);
  } else {
    for (const msg of feedback.slice(0, 5)) {
      const li = document.createElement("li");
      li.textContent = msg;
      els.feedbackList.appendChild(li);
    }
  }
}

/* ============================================================
   GENERATOR (crypto.getRandomValues only)
   ============================================================ */

const CHARSETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  number: "0123456789",
  symbol: "!@#$%^&*()-_=+[]{};:,.<>?/~",
};

const AMBIGUOUS = new Set([..."0OolI1|`'\""]);

/** Uniform random integer in [0, max) using rejection sampling on Web Crypto. */
function randomInt(maxExclusive) {
  const range = 4294967296; // 2^32
  const limit = range - (range % maxExclusive);
  const buf = new Uint32Array(1);
  let v;
  do {
    crypto.getRandomValues(buf);
    v = buf[0];
  } while (v >= limit);
  return v % maxExclusive;
}

function pickRandom(str) {
  return str[randomInt(str.length)];
}

/** Shuffle with Fisher–Yates using secure randomness. */
function secureShuffle(arr) {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function buildPool(opts) {
  let pool = "";
  const groups = [];
  for (const key of ["lower", "upper", "number", "symbol"]) {
    if (!opts[key]) continue;
    let set = CHARSETS[key];
    if (opts.excludeAmbiguous) {
      set = [...set].filter((ch) => !AMBIGUOUS.has(ch)).join("");
    }
    if (set) {
      groups.push(set);
      pool += set;
    }
  }
  return { pool, groups };
}

function generatePassword(opts) {
  const { pool, groups } = buildPool(opts);

  if (!pool) {
    return { error: "Please enable at least one character type (lowercase, uppercase, numbers, or symbols)." };
  }
  if (opts.length < groups.length) {
    return { error: `Length must be at least ${groups.length} to include every selected character type.` };
  }

  // Guarantee each selected character type appears at least once…
  const chars = groups.map((g) => pickRandom(g));

  // …then fill the rest from the combined pool.
  for (let i = chars.length; i < opts.length; i++) {
    chars.push(pickRandom(pool));
  }

  // Shuffle so guaranteed characters aren't predictable at fixed positions.
  const shuffled = secureShuffle(chars);

  return { password: shuffled.join("") };
}

function readGeneratorOptions() {
  return {
    length: parseInt(els.lengthSlider.value, 10),
    lower: els.optLower.checked,
    upper: els.optUpper.checked,
    number: els.optNumber.checked,
    symbol: els.optSymbol.checked,
    excludeAmbiguous: els.optExcludeAmbiguous.checked,
  };
}

function showGeneratorError(msg) {
  els.generatorError.hidden = false;
  els.generatorError.textContent = `⚠️ ${msg}`;
  els.output.value = "";
  els.regenerateBtn.disabled = true;
  els.usePasswordBtn.disabled = true;
}

function clearGeneratorError() {
  els.generatorError.hidden = true;
  els.generatorError.textContent = "";
}

function handleGenerate() {
  const result = generatePassword(readGeneratorOptions());

  if (result.error) {
    showGeneratorError(result.error);
    return;
  }

  clearGeneratorError();
  els.output.value = result.password;
  els.regenerateBtn.disabled = false;
  els.usePasswordBtn.disabled = false;
}

/* ============================================================
   UI helpers
   ============================================================ */

let toastTimer = null;
function showToast(message) {
  els.toast.hidden = false;
  els.toast.textContent = message;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    els.toast.classList.add("hide");
    setTimeout(() => {
      els.toast.hidden = true;
      els.toast.classList.remove("hide");
    }, 300);
  }, 2200);
}

async function copyGenerated() {
  const text = els.output.value;
  if (!text) {
    showToast("Generate a password first.");
    return;
  }
  try {
    await navigator.clipboard.writeText(text);
    showToast("Password copied to clipboard ✓");
    els.copyStatus.textContent = "Copied!";
    setTimeout(() => (els.copyStatus.textContent = ""), 2000);
  } catch {
    // Clipboard API can fail (permissions/insecure context) — fall back.
    let ok = false;
    try {
      els.output.focus();
      els.output.select();
      ok = document.execCommand && document.execCommand("copy");
    } catch { /* ignore */ }
    if (!ok) {
      // Leave the text selected so the user can press Ctrl+C immediately.
      els.output.focus();
      els.output.select();
      showToast("Copy blocked by browser — press Ctrl+C to copy the selected text.");
    } else {
      showToast("Password copied ✓");
    }
  }
}

function toggleVisibility() {
  const showing = els.input.type === "text";
  els.input.type = showing ? "password" : "text";
  els.eyeOpen.hidden = showing;
  els.eyeClosed.hidden = !showing;
  els.toggleVisibility.setAttribute("aria-label", showing ? "Show password" : "Hide password");
  els.toggleVisibility.setAttribute("aria-pressed", String(!showing));
}

function clearInput() {
  els.input.value = "";
  els.input.type = "password";
  els.eyeOpen.hidden = false;
  els.eyeClosed.hidden = true;
  els.toggleVisibility.setAttribute("aria-label", "Show password");
  els.toggleVisibility.setAttribute("aria-pressed", "false");
  renderStrength("");
  els.input.focus();
}

function useGeneratedInAnalyzer() {
  const pw = els.output.value;
  if (!pw) return;
  els.input.value = pw;
  renderStrength(pw);
  showToast("Generated password loaded into analyzer");
  els.analyzerCard?.scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ============================================================
   Wiring
   ============================================================ */

function init() {
  // Analyzer — live analysis as the user types/pastes.
  els.input.addEventListener("input", () => renderStrength(els.input.value));

  els.toggleVisibility.addEventListener("click", toggleVisibility);
  els.clear.addEventListener("click", clearInput);

  // Generator
  els.generateBtn.addEventListener("click", handleGenerate);
  els.regenerateBtn.addEventListener("click", handleGenerate);
  els.copyBtn.addEventListener("click", copyGenerated);
  els.usePasswordBtn.addEventListener("click", useGeneratedInAnalyzer);

  els.lengthSlider.addEventListener("input", () => {
    els.lengthValue.value = els.lengthSlider.value;
    clearGeneratorError();
  });
  for (const cb of [els.optLower, els.optUpper, els.optNumber, els.optSymbol, els.optExcludeAmbiguous]) {
    cb.addEventListener("change", () => {
      clearGeneratorError();
      // Auto-generate on option change if a password is already displayed.
      if (els.output.value) handleGenerate();
    });
  }

  // Initial paint
  els.lengthValue.value = els.lengthSlider.value;
  renderStrength("");

  // Generate one on load so the section isn't empty? No — leave blank so users
  // consciously choose their options first.
}

document.addEventListener("DOMContentLoaded", init);
