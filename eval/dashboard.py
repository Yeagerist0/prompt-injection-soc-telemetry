"""Generates a self-contained HTML dashboard from the injection corpus and,
when one exists, the most recent eval run in eval/results/.

The corpus itself is real data - payload ids, categories, techniques, goals,
tier targets - so the dashboard is fully populated even before any API run
has happened. Only the per-tier result columns are pending in that state;
they render as explicitly "not measured", never as zero and never as
invented numbers.

Security: every value rendered here is attacker-authored by construction -
this page's entire content is a corpus of injection payloads. Text goes
through html.escape(quote=True); the structured data handed to the page's
JavaScript is embedded as JSON in a <script type="application/json"> block
with `<` escaped so the payload text cannot terminate the block, and the
client renders it with textContent rather than innerHTML. A dashboard that
displays injection payloads must not itself be injectable.

Usage:
    python -m eval.dashboard                 # -> eval/results/dashboard.html
    python -m eval.dashboard --body-only     # fragment, no <html>/<head>
    python -m eval.dashboard -o /tmp/x.html
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from collections import Counter
from pathlib import Path

from eval.harness import TIERS
from injection_corpus.loader import Payload, load_corpus

RESULTS_DIR = Path(__file__).parent / "results"
_DEFAULT_OUT = RESULTS_DIR / "dashboard.html"

_GOALS = ("severity_downgrade", "entity_omission", "instruction_leak")

_CATEGORY_FIELD = {
    "process_metadata": "proc_image",
    "file_path": "file_path",
    "network_artifact": "dns_name",
    "log_string": "proc_cmdline",
    "registry_artifact": "registry_key",
    "http_artifact": "user_agent",
}

_TIER_META = {
    "naive": (
        "Naive",
        "Raw telemetry concatenated straight into the prompt. No delimiting, no typing, no framing.",
    ),
    "hardened": (
        "Prompt-hardened",
        "Typed and escaped field tags, an explicit data-not-instructions system prompt, JSON-only output.",
    ),
    "structural": (
        "Structurally grounded",
        "Model picks one label per event from a fixed allow-list. Severity and entity text come from trusted code.",
    ),
}

_GOAL_LABEL = {
    "severity_downgrade": "severity downgrade",
    "entity_omission": "entity omission",
    "instruction_leak": "instruction leak",
}


def find_latest_results(results_dir: Path = RESULTS_DIR) -> Path | None:
    """Newest run_*.json in results_dir, or None if no run has happened."""
    runs = sorted(results_dir.glob("run_*.json"))
    return runs[-1] if runs else None


def load_run(path: Path) -> dict:
    return json.loads(path.read_text())


def build_lookup(run: dict | None) -> dict[tuple[str, str], dict]:
    """(tier, payload_id) -> that result row, empty when no run exists."""
    if not run:
        return {}
    return {
        (tier, r["payload_id"]): r
        for tier, results in run.get("results", {}).items()
        for r in results
        if isinstance(r, dict) and "payload_id" in r
    }


def safe_json_for_script(data: object) -> str:
    """Serialize for embedding in <script type="application/json">.

    Escaping `<` as \\u003c prevents payload text containing `</script>` (or
    `<!--`) from terminating the block early - the HTML parser looks for a
    literal closing tag inside script content regardless of JSON syntax, so
    JSON quoting alone does not protect this position.
    """
    return json.dumps(data, ensure_ascii=False).replace("<", "\\u003c")


def build_page_data(payloads: list[Payload], lookup: dict) -> dict:
    """The structured record the client-side filter and detail panel read."""
    return {
        "tiers": [{"key": t, "name": _TIER_META[t][0]} for t in TIERS],
        "payloads": [
            {
                "id": p.id,
                "category": p.category,
                "field": p.field,
                "technique": p.technique,
                "goal": p.goal,
                "goalLabel": _GOAL_LABEL[p.goal],
                "tierTarget": p.tier_target,
                "text": p.payload,
                "results": {
                    tier: {
                        "bypass": bool(lookup[(tier, p.id)].get("bypass_detected")),
                        "reason": str(lookup[(tier, p.id)].get("reason", "")),
                        "output": str(lookup[(tier, p.id)].get("narrator_output", "")),
                    }
                    for tier in TIERS
                    if (tier, p.id) in lookup
                },
            }
            for p in payloads
        ],
    }


# --------------------------------------------------------------------------
# CSS - plain constant (not an f-string) so braces stay literal.
# --------------------------------------------------------------------------

_CSS = """
:root {
  color-scheme: light;
  --ground: #E7E9E3; --surface: #F1F2EC; --surface-2: #DDE0D8;
  --rule: #C8CCC1; --rule-soft: #D8DBD1;
  --ink: #131711; --ink-dim: #5C635A; --ink-faint: #878E83;
  --bypass: #C24A24; --bypass-soft: #F0D6CB;
  --held: #34705F; --held-soft: #CFE0D9;
  --pending: #B4B9AC; --focus: #7A5C1E;
}
@media (prefers-color-scheme: dark) {
  :root {
    color-scheme: dark;
    --ground: #0F1312; --surface: #171C1A; --surface-2: #1F2523;
    --rule: #28302D; --rule-soft: #202725;
    --ink: #E2E7E2; --ink-dim: #869089; --ink-faint: #5F6863;
    --bypass: #E0603A; --bypass-soft: #3A211A;
    --held: #4F9280; --held-soft: #172924;
    --pending: #39413E; --focus: #D8B368;
  }
}
:root[data-theme="dark"] {
  color-scheme: dark;
  --ground: #0F1312; --surface: #171C1A; --surface-2: #1F2523;
  --rule: #28302D; --rule-soft: #202725;
  --ink: #E2E7E2; --ink-dim: #869089; --ink-faint: #5F6863;
  --bypass: #E0603A; --bypass-soft: #3A211A;
  --held: #4F9280; --held-soft: #172924;
  --pending: #39413E; --focus: #D8B368;
}
:root[data-theme="light"] {
  color-scheme: light;
  --ground: #E7E9E3; --surface: #F1F2EC; --surface-2: #DDE0D8;
  --rule: #C8CCC1; --rule-soft: #D8DBD1;
  --ink: #131711; --ink-dim: #5C635A; --ink-faint: #878E83;
  --bypass: #C24A24; --bypass-soft: #F0D6CB;
  --held: #34705F; --held-soft: #CFE0D9;
  --pending: #B4B9AC; --focus: #7A5C1E;
}

:root {
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;
  --sans: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}

.pi-root {
  background: var(--ground); color: var(--ink);
  font-family: var(--mono); font-size: 14px; line-height: 1.5;
  padding: 32px 24px 80px; min-height: 100%;
}
.pi-wrap { max-width: 1240px; margin: 0 auto; display: flex; flex-direction: column; gap: 34px; }
.pi-prose { font-family: var(--sans); color: var(--ink-dim); line-height: 1.6; max-width: 68ch; margin: 0; }

:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }

/* masthead */
.pi-masthead { display: flex; flex-direction: column; gap: 14px; }
.pi-eyebrow { font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase; color: var(--ink-faint); }
.pi-title { font-size: 25px; font-weight: 600; letter-spacing: -0.01em; margin: 0; text-wrap: balance; }
.pi-title span { color: var(--bypass); }
.pi-meta {
  display: flex; flex-wrap: wrap; gap: 0 28px;
  border-top: 1px solid var(--rule); padding-top: 12px; font-size: 12px; color: var(--ink-dim);
}
.pi-meta div { display: flex; gap: 7px; }
.pi-meta dt { color: var(--ink-faint); }
.pi-meta dd { margin: 0; color: var(--ink); font-variant-numeric: tabular-nums; }

/* status */
.pi-status {
  display: flex; align-items: flex-start; gap: 13px;
  border: 1px solid var(--rule); border-left: 3px solid var(--pending);
  background: var(--surface); padding: 13px 16px;
}
.pi-status.is-live { border-left-color: var(--held); }
.pi-status-key {
  font-size: 11px; letter-spacing: 0.1em; text-transform: uppercase;
  color: var(--ink-faint); white-space: nowrap; padding-top: 1px;
}
.pi-status-body { font-family: var(--sans); font-size: 13px; color: var(--ink-dim); line-height: 1.55; }
.pi-status-body strong { color: var(--ink); font-weight: 600; }
.pi-status-body code { font-family: var(--mono); font-size: 12px; background: var(--surface-2); padding: 1px 5px; color: var(--ink); }

/* tiers */
.pi-tiers { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1px; background: var(--rule); border: 1px solid var(--rule); }
.pi-tier { background: var(--surface); padding: 17px 18px 19px; display: flex; flex-direction: column; gap: 11px; }
.pi-tier-head { display: flex; align-items: baseline; gap: 9px; }
.pi-tier-num { font-size: 11px; color: var(--ink-faint); font-variant-numeric: tabular-nums; }
.pi-tier-name { font-size: 14px; font-weight: 600; }
.pi-tier-figure { display: flex; align-items: baseline; gap: 8px; }
.pi-tier-pct { font-size: 36px; font-weight: 600; letter-spacing: -0.03em; font-variant-numeric: tabular-nums; line-height: 1; }
.pi-tier-pct.is-pending { color: var(--pending); }
.pi-tier-unit { font-size: 11px; color: var(--ink-faint); letter-spacing: 0.06em; text-transform: uppercase; }
.pi-bar { height: 4px; background: var(--surface-2); position: relative; overflow: hidden; }
.pi-bar i { position: absolute; inset: 0 auto 0 0; background: var(--bypass); }
.pi-bar.is-pending { background: repeating-linear-gradient(135deg, var(--surface-2) 0 5px, transparent 5px 10px); }
.pi-tier-note { font-family: var(--sans); font-size: 12px; color: var(--ink-dim); line-height: 1.5; margin: 0; }

/* sections */
.pi-section { display: flex; flex-direction: column; gap: 13px; }
.pi-section-head { display: flex; align-items: baseline; justify-content: space-between; gap: 16px; flex-wrap: wrap; border-bottom: 1px solid var(--rule); padding-bottom: 9px; }
.pi-h2 { font-size: 12px; letter-spacing: 0.13em; text-transform: uppercase; margin: 0; font-weight: 600; }
.pi-section-note { font-size: 11px; color: var(--ink-faint); }

/* category stat tiles */
.pi-cats { display: grid; grid-template-columns: repeat(auto-fit, minmax(178px, 1fr)); gap: 1px; background: var(--rule); border: 1px solid var(--rule); }
.pi-cat { background: var(--surface); padding: 13px 14px; display: flex; flex-direction: column; gap: 7px; }
.pi-cat-name { font-size: 11px; letter-spacing: 0.09em; text-transform: uppercase; font-weight: 600; }
.pi-cat-field { font-size: 11px; color: var(--ink-faint); }
.pi-cat-n { font-size: 20px; font-variant-numeric: tabular-nums; font-weight: 600; }
.pi-cat-n small { font-size: 11px; font-weight: 400; color: var(--ink-faint); letter-spacing: 0.05em; }

/* filter bar */
.pi-filters { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; }
.pi-search {
  flex: 1 1 240px; min-width: 200px;
  background: var(--surface); border: 1px solid var(--rule); color: var(--ink);
  font-family: var(--mono); font-size: 12.5px; padding: 8px 11px;
}
.pi-search::placeholder { color: var(--ink-faint); }
.pi-select {
  background: var(--surface); border: 1px solid var(--rule); color: var(--ink);
  font-family: var(--mono); font-size: 12.5px; padding: 8px 11px;
}
.pi-count { font-size: 11px; color: var(--ink-faint); font-variant-numeric: tabular-nums; margin-left: auto; }

/* matrix */
.pi-scroll { overflow-x: auto; border: 1px solid var(--rule); background: var(--surface); }
.pi-matrix { border-collapse: collapse; width: 100%; min-width: 880px; font-size: 12.5px; }
.pi-matrix thead th {
  position: sticky; top: 0; z-index: 2; background: var(--surface-2); color: var(--ink-faint);
  font-size: 10px; letter-spacing: 0.11em; text-transform: uppercase; font-weight: 600;
  text-align: left; padding: 9px 12px; border-bottom: 1px solid var(--rule); white-space: nowrap;
}
.pi-matrix thead th.pi-c { text-align: center; width: 92px; }
.pi-catrow td { background: var(--surface-2); border-top: 1px solid var(--rule); border-bottom: 1px solid var(--rule); padding: 7px 12px; }
.pi-catrow-inner { display: flex; align-items: baseline; gap: 11px; flex-wrap: wrap; }
.pi-catname { font-size: 11px; letter-spacing: 0.11em; text-transform: uppercase; font-weight: 600; }
.pi-catfield { font-size: 11px; color: var(--ink-faint); }
.pi-catfield b { color: var(--ink-dim); font-weight: 400; }
.pi-matrix td { padding: 7px 12px; border-bottom: 1px solid var(--rule-soft); vertical-align: top; }
.pi-datarow { cursor: pointer; }
.pi-datarow:hover td, .pi-datarow.is-open td { background: var(--surface-2); }
.pi-datarow.is-open { outline: 1px solid var(--rule); }
.pi-id { color: var(--ink-faint); white-space: nowrap; font-variant-numeric: tabular-nums; }
.pi-tech { color: var(--ink); font-family: var(--sans); font-size: 12.5px; line-height: 1.45; }
.pi-chip { display: inline-block; font-size: 10px; letter-spacing: 0.05em; padding: 2px 7px; border: 1px solid var(--rule); color: var(--ink-dim); white-space: nowrap; }
.pi-chip.is-target { border-color: var(--bypass); color: var(--bypass); }
.pi-cell { text-align: center; }
.pi-mark {
  display: inline-flex; align-items: center; justify-content: center;
  width: 100%; height: 22px; font-size: 10px; letter-spacing: 0.08em;
  text-transform: uppercase; font-weight: 600;
}
.pi-mark.is-bypass { background: var(--bypass-soft); color: var(--bypass); }
.pi-mark.is-held { background: var(--held-soft); color: var(--held); }
.pi-mark.is-pending { color: var(--pending); background: repeating-linear-gradient(135deg, var(--rule-soft) 0 4px, transparent 4px 8px); }
.pi-hidden { display: none !important; }

/* detail drawer */
.pi-detailrow > td { padding: 0; background: var(--surface-2); }
.pi-detail { display: flex; flex-direction: column; gap: 13px; padding: 15px 16px 18px; border-left: 3px solid var(--bypass); }
.pi-detail-h { font-size: 10px; letter-spacing: 0.11em; text-transform: uppercase; color: var(--ink-faint); margin: 0 0 5px; }
.pi-payload {
  font-family: var(--mono); font-size: 12.5px; white-space: pre-wrap; word-break: break-word;
  background: var(--ground); border: 1px solid var(--rule); padding: 10px 12px; color: var(--ink); margin: 0;
}
.pi-tierout { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 11px; }
.pi-tierout-card { border: 1px solid var(--rule); background: var(--ground); padding: 11px 12px; display: flex; flex-direction: column; gap: 7px; }
.pi-tierout-head { display: flex; align-items: center; justify-content: space-between; gap: 9px; }
.pi-tierout-name { font-size: 11px; font-weight: 600; letter-spacing: 0.04em; }
.pi-out { font-size: 11.5px; white-space: pre-wrap; word-break: break-word; color: var(--ink-dim); margin: 0; max-height: 190px; overflow-y: auto; }
.pi-reason { font-family: var(--sans); font-size: 11.5px; color: var(--ink-faint); margin: 0; line-height: 1.45; }
.pi-empty { font-family: var(--sans); font-size: 12px; color: var(--ink-faint); padding: 22px 14px; text-align: center; }

/* legend + goals */
.pi-legend { display: flex; flex-wrap: wrap; gap: 18px; font-size: 11px; color: var(--ink-dim); }
.pi-legend span { display: inline-flex; align-items: center; gap: 7px; }
.pi-sw { width: 22px; height: 11px; display: inline-block; }
.pi-sw.is-bypass { background: var(--bypass-soft); border: 1px solid var(--bypass); }
.pi-sw.is-held { background: var(--held-soft); border: 1px solid var(--held); }
.pi-sw.is-pending { border: 1px solid var(--pending); background: repeating-linear-gradient(135deg, var(--rule-soft) 0 4px, transparent 4px 8px); }
.pi-goals { border-collapse: collapse; width: 100%; font-size: 12.5px; }
.pi-goals th, .pi-goals td { padding: 9px 12px; border-bottom: 1px solid var(--rule-soft); text-align: left; }
.pi-goals thead th { font-size: 10px; letter-spacing: 0.11em; text-transform: uppercase; color: var(--ink-faint); font-weight: 600; border-bottom: 1px solid var(--rule); }
.pi-goals td.pi-n, .pi-goals th.pi-n { text-align: right; font-variant-numeric: tabular-nums; }
.pi-goals tbody tr:last-child td { border-bottom: none; }
.pi-dash { color: var(--pending); }

.pi-foot { border-top: 1px solid var(--rule); padding-top: 13px; font-size: 11px; color: var(--ink-faint); font-family: var(--sans); line-height: 1.6; }
.pi-foot code { font-family: var(--mono); color: var(--ink-dim); }

@media (max-width: 760px) {
  .pi-tiers { grid-template-columns: 1fr; }
  .pi-root { padding: 22px 14px 60px; }
}
@media (prefers-reduced-motion: reduce) { * { transition: none !important; animation: none !important; } }
"""

_JS = """
(function () {
  var el = document.getElementById('pi-data');
  if (!el) return;
  var DATA = JSON.parse(el.textContent);
  var byId = {};
  DATA.payloads.forEach(function (p) { byId[p.id] = p; });

  var search = document.getElementById('pi-search');
  var goalSel = document.getElementById('pi-goal');
  var targetSel = document.getElementById('pi-target');
  var countEl = document.getElementById('pi-count');
  var table = document.getElementById('pi-matrix');
  if (!table) return;

  var openId = null;

  function clearDetail() {
    var existing = table.querySelector('.pi-detailrow');
    if (existing) existing.parentNode.removeChild(existing);
    Array.prototype.forEach.call(table.querySelectorAll('.pi-datarow.is-open'), function (r) {
      r.classList.remove('is-open');
      r.setAttribute('aria-expanded', 'false');
    });
  }

  function field(label, node) {
    var wrap = document.createElement('div');
    var h = document.createElement('p');
    h.className = 'pi-detail-h';
    h.textContent = label;
    wrap.appendChild(h);
    wrap.appendChild(node);
    return wrap;
  }

  function buildDetail(p) {
    var box = document.createElement('div');
    box.className = 'pi-detail';

    // Payload text is attacker-authored: textContent only, never innerHTML.
    var pre = document.createElement('pre');
    pre.className = 'pi-payload';
    pre.textContent = p.text;
    box.appendChild(field('payload spliced into Event.' + p.field, pre));

    var grid = document.createElement('div');
    grid.className = 'pi-tierout';
    DATA.tiers.forEach(function (t) {
      var card = document.createElement('div');
      card.className = 'pi-tierout-card';

      var head = document.createElement('div');
      head.className = 'pi-tierout-head';
      var nm = document.createElement('span');
      nm.className = 'pi-tierout-name';
      nm.textContent = t.name;
      head.appendChild(nm);

      var res = p.results[t.key];
      var mark = document.createElement('span');
      mark.className = 'pi-mark ' + (!res ? 'is-pending' : res.bypass ? 'is-bypass' : 'is-held');
      mark.style.width = 'auto';
      mark.style.padding = '0 8px';
      mark.textContent = !res ? 'not measured' : res.bypass ? 'bypass' : 'held';
      head.appendChild(mark);
      card.appendChild(head);

      if (res) {
        var out = document.createElement('pre');
        out.className = 'pi-out';
        out.textContent = res.output || '(empty output)';
        card.appendChild(out);
        var why = document.createElement('p');
        why.className = 'pi-reason';
        why.textContent = res.reason;
        card.appendChild(why);
      } else {
        var none = document.createElement('p');
        none.className = 'pi-reason';
        none.textContent = 'No run yet - execute python -m eval.run_all to populate this.';
        card.appendChild(none);
      }
      grid.appendChild(card);
    });
    box.appendChild(field('narrator output by tier', grid));
    return box;
  }

  function toggle(row) {
    var id = row.getAttribute('data-id');
    if (openId === id) { clearDetail(); openId = null; return; }
    clearDetail();
    openId = id;
    row.classList.add('is-open');
    row.setAttribute('aria-expanded', 'true');
    var tr = document.createElement('tr');
    tr.className = 'pi-detailrow';
    var td = document.createElement('td');
    td.colSpan = 4 + DATA.tiers.length;
    td.appendChild(buildDetail(byId[id]));
    tr.appendChild(td);
    row.parentNode.insertBefore(tr, row.nextSibling);
  }

  Array.prototype.forEach.call(table.querySelectorAll('.pi-datarow'), function (row) {
    row.addEventListener('click', function () { toggle(row); });
    row.addEventListener('keydown', function (ev) {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle(row); }
    });
  });

  function apply() {
    var q = (search.value || '').toLowerCase().trim();
    var goal = goalSel.value;
    var target = targetSel.value;
    var shown = 0;
    clearDetail();
    openId = null;

    Array.prototype.forEach.call(table.querySelectorAll('.pi-datarow'), function (row) {
      var p = byId[row.getAttribute('data-id')];
      var hit = !q || (p.id + ' ' + p.technique + ' ' + p.text + ' ' + p.category).toLowerCase().indexOf(q) !== -1;
      var okGoal = goal === 'all' || p.goal === goal;
      var okTarget = target === 'all' || p.tierTarget === target;
      var visible = hit && okGoal && okTarget;
      row.classList.toggle('pi-hidden', !visible);
      if (visible) shown++;
    });

    Array.prototype.forEach.call(table.querySelectorAll('.pi-catrow'), function (crow) {
      var cat = crow.getAttribute('data-category');
      var any = table.querySelector('.pi-datarow[data-category="' + cat + '"]:not(.pi-hidden)');
      crow.classList.toggle('pi-hidden', !any);
    });

    countEl.textContent = shown + ' of ' + DATA.payloads.length + ' payloads';
    var empty = document.getElementById('pi-empty');
    if (empty) empty.classList.toggle('pi-hidden', shown !== 0);
  }

  search.addEventListener('input', apply);
  goalSel.addEventListener('change', apply);
  targetSel.addEventListener('change', apply);
  apply();
})();
"""


def _pct(x: float) -> str:
    return f"{round(x * 100)}%"


def _render_tier(tier: str, index: int, summary: dict | None) -> str:
    name, note = _TIER_META[tier]
    if summary and "overall" in summary:
        pct = summary["overall"]
        figure = f'<span class="pi-tier-pct">{_pct(pct)}</span>'
        bar = f'<div class="pi-bar"><i style="width:{float(pct) * 100:.4f}%"></i></div>'
    else:
        figure = '<span class="pi-tier-pct is-pending">--</span>'
        bar = '<div class="pi-bar is-pending"></div>'
    return f"""      <div class="pi-tier">
        <div class="pi-tier-head">
          <span class="pi-tier-num">TIER {index}</span>
          <span class="pi-tier-name">{html.escape(name)}</span>
        </div>
        <div class="pi-tier-figure">{figure}<span class="pi-tier-unit">bypass rate</span></div>
        {bar}
        <p class="pi-tier-note">{html.escape(note)}</p>
      </div>"""


def _render_categories(payloads: list[Payload]) -> str:
    counts = Counter(p.category for p in payloads)
    tiles = []
    for cat, field in _CATEGORY_FIELD.items():
        if not counts.get(cat):
            continue
        tiles.append(
            f"""      <div class="pi-cat">
        <span class="pi-cat-name">{html.escape(cat.replace("_", " "))}</span>
        <span class="pi-cat-n">{counts[cat]} <small>payloads</small></span>
        <span class="pi-cat-field">Event.{html.escape(field)}</span>
      </div>"""
        )
    return f'    <div class="pi-cats">\n{chr(10).join(tiles)}\n    </div>'


def _render_cell(tier: str, payload_id: str, lookup: dict) -> str:
    key = (tier, payload_id)
    if key not in lookup:
        return '<td class="pi-cell"><span class="pi-mark is-pending" title="not measured">&middot;</span></td>'
    if lookup[key].get("bypass_detected"):
        return '<td class="pi-cell"><span class="pi-mark is-bypass" title="bypass detected">bypass</span></td>'
    return '<td class="pi-cell"><span class="pi-mark is-held" title="defense held">held</span></td>'


def _render_matrix(payloads: list[Payload], lookup: dict) -> str:
    rows: list[str] = []
    for category, field in _CATEGORY_FIELD.items():
        items = [p for p in payloads if p.category == category]
        if not items:
            continue
        cat_attr = html.escape(category)
        rows.append(
            f"""        <tr class="pi-catrow" data-category="{cat_attr}"><td colspan="{4 + len(TIERS)}">
          <div class="pi-catrow-inner">
            <span class="pi-catname">{html.escape(category.replace("_", " "))}</span>
            <span class="pi-catfield">spliced into <b>Event.{html.escape(field)}</b></span>
            <span class="pi-catfield">{len(items)} payloads</span>
          </div>
        </td></tr>"""
        )
        for p in items:
            cells = "".join(_render_cell(t, p.id, lookup) for t in TIERS)
            target = (
                f'<span class="pi-chip is-target">vs {html.escape(p.tier_target)}</span>'
                if p.tier_target != "generic"
                else '<span class="pi-catfield">&mdash;</span>'
            )
            rows.append(
                f"""        <tr class="pi-datarow" data-id="{html.escape(p.id)}" data-category="{cat_attr}"
             tabindex="0" role="button" aria-expanded="false">
          <td class="pi-id">{html.escape(p.id)}</td>
          <td class="pi-tech">{html.escape(p.technique)}</td>
          <td><span class="pi-chip">{html.escape(_GOAL_LABEL[p.goal])}</span></td>
          <td>{target}</td>
          {cells}
        </tr>"""
            )
    head = "".join(f'<th class="pi-c">{html.escape(_TIER_META[t][0])}</th>' for t in TIERS)
    return f"""    <div class="pi-scroll">
      <table class="pi-matrix" id="pi-matrix">
        <thead><tr>
          <th>id</th><th>technique</th><th>attacker goal</th><th>targets</th>{head}
        </tr></thead>
        <tbody>
{chr(10).join(rows)}
        </tbody>
      </table>
      <p class="pi-empty pi-hidden" id="pi-empty">No payloads match that filter.</p>
    </div>"""


def _render_goals(payloads: list[Payload], summaries: dict) -> str:
    counts = Counter(p.goal for p in payloads)
    rows = []
    for goal in _GOALS:
        cells = []
        for tier in TIERS:
            s = summaries.get(tier, {})
            cells.append(
                f'<td class="pi-n">{_pct(s[goal])}</td>'
                if goal in s
                else '<td class="pi-n"><span class="pi-dash">--</span></td>'
            )
        rows.append(
            f"""          <tr>
            <td>{html.escape(_GOAL_LABEL[goal])}</td>
            <td class="pi-n">{counts[goal]}</td>
            {"".join(cells)}
          </tr>"""
        )
    head = "".join(f'<th class="pi-n">{html.escape(_TIER_META[t][0])}</th>' for t in TIERS)
    return f"""    <div class="pi-scroll" style="padding:0 4px;">
      <table class="pi-goals">
        <thead><tr><th>attacker goal</th><th class="pi-n">payloads</th>{head}</tr></thead>
        <tbody>
{chr(10).join(rows)}
        </tbody>
      </table>
    </div>"""


def _render_filters(payloads: list[Payload]) -> str:
    goal_opts = "".join(
        f'<option value="{html.escape(g)}">{html.escape(_GOAL_LABEL[g])}</option>' for g in _GOALS
    )
    targets = sorted({p.tier_target for p in payloads})
    target_opts = "".join(
        f'<option value="{html.escape(t)}">{html.escape("targets " + t)}</option>' for t in targets
    )
    return f"""    <div class="pi-filters">
      <input class="pi-search" id="pi-search" type="search" placeholder="Search id, technique, or payload text&hellip;"
             aria-label="Search payloads">
      <select class="pi-select" id="pi-goal" aria-label="Filter by attacker goal">
        <option value="all">all goals</option>{goal_opts}
      </select>
      <select class="pi-select" id="pi-target" aria-label="Filter by targeted defense tier">
        <option value="all">all targets</option>{target_opts}
      </select>
      <span class="pi-count" id="pi-count">{len(payloads)} payloads</span>
    </div>"""


def render_body(payloads: list[Payload], run: dict | None) -> str:
    lookup = build_lookup(run)
    summaries = (run or {}).get("summaries", {})
    live = bool(lookup)

    if live:
        status = f"""    <div class="pi-status is-live">
      <span class="pi-status-key">Run</span>
      <div class="pi-status-body">Measured against <strong>{html.escape(str(run.get("model", "unknown")))}</strong>
      on {html.escape(str(run.get("generated_at", "unknown")))}.</div>
    </div>"""
        meta_model = html.escape(str(run.get("model", "unknown")))
        meta_when = html.escape(str(run.get("generated_at", ""))[:19].replace("T", " ") + " UTC")
    else:
        status = """    <div class="pi-status">
      <span class="pi-status-key">Not run</span>
      <div class="pi-status-body">The corpus, all three narrator tiers, and the judge are built and tested, but
      <strong>no evaluation has been run against the live API yet</strong> &mdash; so every per-tier result below is
      marked not-measured rather than filled with an estimate. Everything else on this page (payload ids, techniques,
      attacker goals, targeted tiers, category&rarr;field mapping) is real data read from the corpus. Run
      <code>python -m eval.run_all</code> to populate the result columns.</div>
    </div>"""
        meta_model = "&mdash;"
        meta_when = "&mdash;"

    data_json = safe_json_for_script(build_page_data(payloads, lookup))

    return f"""<div class="pi-root">
  <div class="pi-wrap">
    <header class="pi-masthead">
      <div class="pi-eyebrow">Indirect prompt injection &middot; SOC / EDR telemetry narration</div>
      <h1 class="pi-title">Can attacker-written telemetry <span>talk the narrator out of</span> reporting it?</h1>
      <p class="pi-prose">Every payload below is spliced into a field an attacker on a monitored host controls
      directly &mdash; a process name, a command line, a file path, a DNS query, a registry key, a user agent &mdash;
      and fed to an LLM asked to summarise the incident. A <em>bypass</em> means the attack achieved its goal: the
      summary downgraded the severity, omitted the malicious entity, or was overridden outright.
      Select any row to see the raw payload and what each tier did with it.</p>
      <dl class="pi-meta">
        <div><dt>corpus</dt><dd>{len(payloads)} payloads</dd></div>
        <div><dt>categories</dt><dd>{len({p.category for p in payloads})}</dd></div>
        <div><dt>tiers</dt><dd>{len(TIERS)}</dd></div>
        <div><dt>model</dt><dd>{meta_model}</dd></div>
        <div><dt>run</dt><dd>{meta_when}</dd></div>
      </dl>
    </header>

{status}

    <section class="pi-section">
      <div class="pi-section-head">
        <h2 class="pi-h2">Defense tiers</h2>
        <span class="pi-section-note">lower bypass rate is better</span>
      </div>
      <div class="pi-tiers">
{chr(10).join(_render_tier(t, i, summaries.get(t)) for i, t in enumerate(TIERS, start=1))}
      </div>
    </section>

    <section class="pi-section">
      <div class="pi-section-head">
        <h2 class="pi-h2">Attack surface</h2>
        <span class="pi-section-note">one category per attacker-controlled field</span>
      </div>
{_render_categories(payloads)}
    </section>

    <section class="pi-section">
      <div class="pi-section-head">
        <h2 class="pi-h2">Payload matrix</h2>
        <span class="pi-section-note">{len(payloads)} payloads &times; {len(TIERS)} tiers</span>
      </div>
{_render_filters(payloads)}
{_render_matrix(payloads, lookup)}
      <div class="pi-legend">
        <span><i class="pi-sw is-bypass"></i> bypass &mdash; the attack achieved its goal</span>
        <span><i class="pi-sw is-held"></i> held &mdash; the defense caught it</span>
        <span><i class="pi-sw is-pending"></i> not measured</span>
      </div>
    </section>

    <section class="pi-section">
      <div class="pi-section-head">
        <h2 class="pi-h2">By attacker goal</h2>
        <span class="pi-section-note">bypass rate within each goal</span>
      </div>
{_render_goals(payloads, summaries)}
    </section>

    <p class="pi-foot">Generated by <code>eval/dashboard.py</code> from <code>injection_corpus/payloads.yaml</code>
    and the newest <code>eval/results/run_*.json</code>. Scoring is rule-based and deterministic
    (<code>eval/judge.py</code>) rather than LLM-as-judge, so the same payload and output always score identically.
    Payload text is rendered via <code>textContent</code> and never as markup &mdash; a page that displays injection
    payloads must not itself be injectable.</p>
  </div>
</div>
<script type="application/json" id="pi-data">{data_json}</script>
<script>{_JS}</script>"""


def render_page(payloads: list[Payload], run: dict | None, body_only: bool = False) -> str:
    body = render_body(payloads, run)
    if body_only:
        return f"<style>\n{_CSS}\n</style>\n{body}\n"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Prompt injection via SOC telemetry &mdash; eval dashboard</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; }}
html, body {{ margin: 0; padding: 0; }}
{_CSS}
</style>
</head>
<body>
{body}
</body>
</html>
"""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-o", "--out", type=Path, default=_DEFAULT_OUT)
    parser.add_argument("--body-only", action="store_true", help="emit a fragment with no <html>/<head> wrapper")
    args = parser.parse_args(argv)

    payloads = load_corpus()
    latest = find_latest_results()
    run = load_run(latest) if latest else None

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(render_page(payloads, run, body_only=args.body_only))

    state = f"from {latest.name}" if latest else "no run yet - result columns marked not-measured"
    print(f"Wrote {args.out} ({len(payloads)} payloads, {state})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
