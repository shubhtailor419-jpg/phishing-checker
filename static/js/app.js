"use strict";

(function () {
  const form = document.getElementById("check-form");
  if (!form) return;

  const input = document.getElementById("content");
  const label = document.getElementById("content-label");
  const panel = document.getElementById("panel");
  const submit = document.getElementById("submit");
  const errorBox = document.getElementById("error");
  const resultBox = document.getElementById("result");
  const historyCard = document.getElementById("history-card");
  const historyList = document.getElementById("history");
  const clearBtn = document.getElementById("clear-history");
  const tabs = Array.from(document.querySelectorAll('[role="tab"]'));

  const MODES = {
    url: {
      rows: 2,
      max: Number(input.dataset.maxUrl),
      placeholder: "https://example.com/login",
      label: "Paste a link to check",
    },
    email: {
      rows: 8,
      max: Number(input.dataset.maxEmail),
      placeholder: "Paste the email or SMS text here, including any links...",
      label: "Paste the message to check",
    },
  };
  const ART = {
    low: resultBox.dataset.artLow,
    medium: resultBox.dataset.artMedium,
    high: resultBox.dataset.artHigh,
  };
  const HISTORY_KEY = "pc_history_v1";
  const HISTORY_MAX = 8;
  const SVG_NS = "http://www.w3.org/2000/svg";
  let mode = "url";

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = text;
    return node;
  }

  function svg(tag, attrs) {
    const node = document.createElementNS(SVG_NS, tag);
    Object.keys(attrs || {}).forEach((k) => node.setAttribute(k, attrs[k]));
    return node;
  }

  function truncate(text, limit) {
    return text.length > limit ? text.slice(0, limit - 1) + "…" : text;
  }

  function setMode(next, focusInput) {
    mode = next;
    const cfg = MODES[next];
    tabs.forEach((tab) => {
      const active = tab.dataset.mode === next;
      tab.setAttribute("aria-selected", String(active));
      tab.tabIndex = active ? 0 : -1;
      if (active) panel.setAttribute("aria-labelledby", tab.id);
    });
    input.rows = cfg.rows;
    input.maxLength = cfg.max;
    input.placeholder = cfg.placeholder;
    label.textContent = cfg.label;
    if (focusInput) input.focus();
  }

  tabs.forEach((tab, index) => {
    tab.addEventListener("click", () => setMode(tab.dataset.mode, true));
    tab.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
      const next = tabs[(index + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length];
      setMode(next.dataset.mode, false);
      next.focus();
    });
  });

  function showError(message) {
    errorBox.textContent = message;
    errorBox.hidden = false;
  }
  function clearError() {
    errorBox.textContent = "";
    errorBox.hidden = true;
  }

  function buildGauge(score) {
    const radius = 52;
    const circumference = 2 * Math.PI * radius;
    const root = svg("svg", {
      viewBox: "0 0 120 120",
      class: "gauge",
      role: "img",
      "aria-label": "Risk score " + score + " out of 100",
    });
    root.appendChild(svg("circle", { class: "gauge-track", cx: 60, cy: 60, r: radius }));
    const bar = svg("circle", {
      class: "gauge-bar", cx: 60, cy: 60, r: radius,
      transform: "rotate(-90 60 60)",
      "stroke-dasharray": circumference.toFixed(2),
    });
    bar.style.strokeDashoffset = circumference.toFixed(2);
    root.appendChild(bar);

    const number = svg("text", { class: "gauge-score", x: 60, y: 64 });
    number.textContent = String(score);
    const max = svg("text", { class: "gauge-max", x: 60, y: 82 });
    max.textContent = "OUT OF 100";
    root.appendChild(number);
    root.appendChild(max);

    requestAnimationFrame(() => requestAnimationFrame(() => {
      bar.style.strokeDashoffset = (circumference * (1 - score / 100)).toFixed(2);
    }));
    return root;
  }

  function renderResult(data) {
    resultBox.replaceChildren();
    resultBox.dataset.level = data.level;

    const head = el("div", "result-head");
    head.appendChild(buildGauge(data.score));
    const text = el("div", "result-text");
    text.appendChild(el("p", "verdict", data.verdict));
    text.appendChild(el("p", "subject", truncate(data.subject, 120)));
    head.appendChild(text);

    const art = el("img", "result-art");
    art.src = ART[data.level] || ART.low;
    art.alt = "";
    art.width = 580;
    art.height = 320;
    head.appendChild(art);
    resultBox.appendChild(head);

    resultBox.appendChild(el("p", "advice", data.advice));
    resultBox.appendChild(el("h3", null, "Why this score"));

    if (!data.findings.length) {
      resultBox.appendChild(el("p", "none", "None of the checks found anything unusual."));
    } else {
      const list = el("ul", "findings");
      data.findings.forEach((f) => {
        const item = el("li", "finding");
        item.appendChild(el("span", "dot sev-" + f.severity));
        item.appendChild(el("span", "finding-title", f.title));
        if (f.points > 0) item.appendChild(el("span", "points", "+" + f.points));
        else item.appendChild(el("span"));
        if (f.detail) item.appendChild(el("p", "finding-detail", f.detail));
        list.appendChild(item);
      });
      resultBox.appendChild(list);
    }

    resultBox.hidden = false;
    resultBox.focus({ preventScroll: true });
    resultBox.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function loadHistory() {
    try {
      const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
      return Array.isArray(parsed) ? parsed : [];
    } catch (err) {
      return [];
    }
  }

  function storeHistory(items) {
    try {
      localStorage.setItem(HISTORY_KEY, JSON.stringify(items));
    } catch (err) {}
  }

  function renderHistory(items) {
    historyList.replaceChildren();
    historyCard.hidden = items.length === 0;
    items.forEach((entry) => {
      const li = el("li");
      li.appendChild(el("span", "h-kind", entry.kind === "email" ? "Text" : "Link"));
      li.appendChild(el("span", "h-text", entry.preview));
      const score = el("span", "h-score");
      score.appendChild(el("span", "dot " + entry.level));
      score.appendChild(document.createTextNode(entry.score + "/100"));
      li.appendChild(score);
      historyList.appendChild(li);
    });
  }

  function remember(data) {

    const entry = {
      kind: data.kind,
      preview: truncate(data.subject, 60),
      score: data.score,
      level: data.level,
    };
    const items = [entry].concat(loadHistory()).slice(0, HISTORY_MAX);
    storeHistory(items);
    renderHistory(items);
  }

  clearBtn.addEventListener("click", () => {
    storeHistory([]);
    renderHistory([]);
  });

  async function run() {
    const value = input.value.trim();
    if (!value) {
      showError("Please paste something to check.");
      input.focus();
      return;
    }
    clearError();
    submit.disabled = true;
    submit.textContent = "Checking…";
    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ type: mode, content: value }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(data.error || "Something went wrong. Please try again.");
      }
      renderResult(data);
      remember(data);
    } catch (err) {
      showError(err instanceof TypeError
        ? "Could not reach the server. Check your connection and try again."
        : err.message);
    } finally {
      submit.disabled = false;
      submit.textContent = "Check it";
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    run();
  });

  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      run();
    } else if (event.key === "Enter" && mode === "url" && !event.shiftKey) {
      event.preventDefault();
      run();
    }
  });

  document.querySelectorAll(".examples [data-text]").forEach((button) => {
    button.addEventListener("click", () => {
      setMode(button.dataset.mode, false);
      input.value = button.dataset.text;
      run();
    });
  });

  setMode("url", false);
  renderHistory(loadHistory());
})();
