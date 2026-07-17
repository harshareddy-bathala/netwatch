/**
 * AskView.js - Ask NetWatch (Phase 3, LLM investigations)
 * ========================================================
 * A chat view over /api/investigate.  You ask a question in plain
 * language; a local LLM answers using only the read-only grounding tools
 * and the answer shows its citations and the exact tool calls made — the
 * explainability contract.
 *
 * When no local model is reachable the view says so and points at the
 * fix (install Ollama + pull a model); it never pretends to answer.
 *
 * All rendered text (answers, tool results) comes from the model / DB, so
 * every write uses textContent / DOM APIs — never HTML interpolation.
 */

import api from '../api.js';

const SUGGESTIONS = [
  'Are there any open incidents right now?',
  'How much bandwidth is the network using?',
  'Which devices are talking to external hosts?',
  'Summarise the current state of the network.',
];

// Persist the conversation across view remounts (navigating away and back)
// so Ask NetWatch doesn't start fresh every time. Session-scoped, in-memory.
let _savedThreadHTML = null;

export default class AskView {
  constructor(el) {
    this.el = el;
    this._destroyed = false;
    this._busy = false;
    this._history = [];   // {role: 'user'|'assistant', ...}
    this._available = null;   // null = unknown, true/false once checked
    this._offlineReason = '';
    this._model = '';
  }

  render() {
    this.el.innerHTML = `
      <div class="ask">
        <div class="ask__status" id="ask-status"></div>
        <div class="ask__thread" id="ask-thread">
          <div class="ask__intro">
            <h3>Ask NetWatch</h3>
            <p>Ask about your network in plain language. Answers are grounded
               in live data and show their sources.</p>
            <div class="ask__suggestions" id="ask-suggestions"></div>
          </div>
        </div>
        <form class="ask__composer" id="ask-form">
          <input type="text" id="ask-input" class="ask__input" autocomplete="off"
                 placeholder="Ask a question about your network…" />
          <button type="submit" class="btn btn--primary" id="ask-send">Ask</button>
        </form>
      </div>
    `;

    const sugg = this.el.querySelector('#ask-suggestions');
    for (const s of SUGGESTIONS) {
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'ask__suggestion';
      chip.textContent = s;
      chip.addEventListener('click', () => {
        this.el.querySelector('#ask-input').value = s;
        this._submit();
      });
      sugg.appendChild(chip);
    }

    this.el.querySelector('#ask-form').addEventListener('submit', e => {
      e.preventDefault();
      this._submit();
    });

    // Restore a prior conversation if the user navigated away and back.
    if (_savedThreadHTML) {
      const thread = this._thread();
      if (thread) {
        thread.innerHTML = _savedThreadHTML;
        this._scroll();
      }
    }

    this._checkStatus();
  }

  destroy() {
    this._destroyed = true;
    // Save the conversation (unless it's just the intro) so it survives a
    // remount. Cheap: the thread is small text.
    const thread = this._thread();
    if (thread && !thread.querySelector('.ask__intro')) {
      _savedThreadHTML = thread.innerHTML;
    }
  }

  async _checkStatus() {
    const statusEl = this.el.querySelector('#ask-status');
    if (!statusEl) return;
    const resp = await api.getInvestigateStatus();
    if (this._destroyed) return;
    const data = (resp && resp.data) || {};
    this._available = !!data.available;
    this._offlineReason = data.reason || '';
    this._model = data.model || '';
    if (data.available) {
      statusEl.className = 'ask__status ask__status--ok';
      statusEl.textContent =
        `Local model ready${this._model ? ` (${this._model})` : ''} — ` +
        'answers are grounded in live network data and cite their sources.';
    } else {
      statusEl.className = 'ask__status ask__status--off';
      statusEl.textContent = this._offlineReason ||
        'No local model running. Install Ollama and run `ollama pull llama3.2:3b` ' +
        'to enable Ask NetWatch — everything stays on this machine.';
    }
  }

  async _submit() {
    if (this._busy) return;
    const input = this.el.querySelector('#ask-input');
    const question = (input.value || '').trim();
    if (!question) return;

    input.value = '';
    this._appendUser(question);

    // Known-offline: answer instantly instead of a doomed slow round-trip,
    // and re-check in the background in case Ollama just came up.
    if (this._available === false) {
      this._appendNotice(this._offlineReason || 'Investigations are unavailable.');
      this._checkStatus();
      return;
    }

    this._busy = true;
    this._setSending(true);
    const thinking = this._appendThinking();

    try {
      const resp = await api.investigate(question);
      if (this._destroyed) return;
      thinking.remove();
      if (resp && resp.error) {
        // Transport-level failure (timeout, server error) — say so plainly
        // rather than rendering an empty bubble as "(no answer)".
        this._appendNotice(
          resp.aborted
            ? 'The investigation is taking longer than expected and was stopped. ' +
              'On a low-memory machine the local model can be slow — try a ' +
              'simpler question, or a smaller/faster model.'
            : (resp.message || 'Something went wrong reaching the investigator.'));
      } else {
        const data = (resp && resp.data) || {};
        if (data.available === false) {
          this._available = false;
          this._offlineReason = data.reason || '';
          this._checkStatus();
          this._appendNotice(data.reason || 'Investigations are unavailable.');
        } else {
          // A real answer proves the model is up — clear any stale
          // "no model running" banner (it may have been shown before Ollama
          // finished starting).
          if (!this._available) {
            this._available = true;
            this._checkStatus();
          }
          this._appendAnswer(data);
        }
      }
    } catch (err) {
      thinking.remove();
      this._appendNotice('Something went wrong reaching the investigator.');
    } finally {
      this._busy = false;
      this._setSending(false);
      this._scroll();
    }
  }

  _setSending(sending) {
    const btn = this.el.querySelector('#ask-send');
    if (btn) {
      btn.disabled = sending;
      btn.textContent = sending ? 'Thinking…' : 'Ask';
    }
  }

  _thread() {
    return this.el.querySelector('#ask-thread');
  }

  _appendUser(text) {
    const intro = this.el.querySelector('.ask__intro');
    if (intro) intro.remove();
    const row = document.createElement('div');
    row.className = 'ask-msg ask-msg--user';
    const bubble = document.createElement('div');
    bubble.className = 'ask-msg__bubble';
    bubble.textContent = text;
    row.appendChild(bubble);
    this._thread().appendChild(row);
    this._scroll();
  }

  _appendThinking() {
    const row = document.createElement('div');
    row.className = 'ask-msg ask-msg--assistant';
    const bubble = document.createElement('div');
    bubble.className = 'ask-msg__bubble ask-msg__bubble--thinking';
    const label = this._model ? `Investigating with ${this._model}…` : 'Investigating…';
    bubble.textContent = label;
    row.appendChild(bubble);
    this._thread().appendChild(row);
    this._scroll();

    // Elapsed-time ticker: a local model legitimately takes tens of
    // seconds — show that it is working, not hung.
    const started = Date.now();
    const timer = setInterval(() => {
      const secs = Math.round((Date.now() - started) / 1000);
      if (secs >= 5) bubble.textContent = `${label} ${secs}s`;
      if (secs >= 30) {
        bubble.textContent =
          `${label} ${secs}s — the model is retrieving and reasoning over ` +
          'live data; slower machines can take a minute or two.';
      }
    }, 1000);
    const origRemove = row.remove.bind(row);
    row.remove = () => { clearInterval(timer); origRemove(); };
    return row;
  }

  _appendAnswer(data) {
    const row = document.createElement('div');
    row.className = 'ask-msg ask-msg--assistant';

    const bubble = document.createElement('div');
    bubble.className = 'ask-msg__bubble';

    const answer = document.createElement('div');
    answer.className = 'ask-msg__answer';
    answer.textContent = data.answer || '(no answer)';
    bubble.appendChild(answer);

    // Citations
    const citations = Array.isArray(data.citations) ? data.citations : [];
    if (citations.length) {
      const cite = document.createElement('div');
      cite.className = 'ask-msg__citations';
      cite.textContent = 'Sources: ';
      for (const c of citations) {
        const tag = document.createElement('span');
        tag.className = 'ask-cite';
        tag.textContent = c;
        cite.appendChild(tag);
      }
      bubble.appendChild(cite);
    }

    // Tool-call trace (explainability) — collapsed by default
    const calls = Array.isArray(data.tool_calls) ? data.tool_calls : [];
    const realCalls = calls.filter(c => c.tool);
    if (realCalls.length) {
      const details = document.createElement('details');
      details.className = 'ask-msg__trace';
      const summary = document.createElement('summary');
      summary.textContent =
        `${realCalls.length} tool call${realCalls.length === 1 ? '' : 's'}`;
      details.appendChild(summary);
      for (const call of realCalls) {
        const line = document.createElement('div');
        line.className = 'ask-trace__call';
        line.textContent =
          `${call.tool}(${JSON.stringify(call.params || {})})`;
        details.appendChild(line);
      }
      bubble.appendChild(details);
    }

    row.appendChild(bubble);
    this._thread().appendChild(row);
    this._scroll();
  }

  _appendNotice(text) {
    const row = document.createElement('div');
    row.className = 'ask-msg ask-msg--notice';
    const bubble = document.createElement('div');
    bubble.className = 'ask-msg__bubble ask-msg__bubble--notice';
    bubble.textContent = text;
    row.appendChild(bubble);
    this._thread().appendChild(row);
    this._scroll();
  }

  _scroll() {
    const thread = this._thread();
    if (thread) thread.scrollTop = thread.scrollHeight;
  }
}
