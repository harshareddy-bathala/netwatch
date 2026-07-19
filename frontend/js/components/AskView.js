/**
 * AskView.js - Ask NetWatch (Phase 3, LLM investigations)
 * ========================================================
 * A chat view over /api/investigate.  You ask a question in plain
 * language; a local LLM answers using only the read-only grounding tools
 * and the answer shows its citations and the exact tool calls made — the
 * explainability contract.
 *
 * Conversation state lives in a module-level store, NOT in the component.
 * A local model takes tens of seconds, so a question asked here must keep
 * running while the user browses Devices or Topology — the answer lands in
 * the store whether or not this view is mounted, and remounting replays it.
 * The component is a pure renderer over that store.
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

/**
 * Session-scoped conversation store. Survives view unmount/remount so an
 * investigation started here completes even if the user navigates away.
 */
const conversation = {
  messages: [],        // {role: 'user'|'answer'|'notice', text, data}
  pending: false,      // an investigation is in flight
  startedAt: 0,        // ms epoch, for the elapsed ticker
  available: null,     // null = unknown, true/false once checked
  offlineReason: '',
  _listeners: new Set(),

  subscribe(fn) { this._listeners.add(fn); return () => this._listeners.delete(fn); },
  _emit() { for (const fn of this._listeners) { try { fn(); } catch { /* view gone */ } } },
  add(msg) { this.messages.push(msg); this._emit(); },
  reset() {
    // Deliberately does NOT cancel an in-flight request — the fetch has no
    // abort handle here; instead the result is dropped on arrival (see the
    // generation guard in ask()).
    this.messages = [];
    this.pending = false;
    this.startedAt = 0;
    this._generation++;
    this._emit();
  },
  _generation: 0,
};

/**
 * Run an investigation. Lives outside the component so it keeps going after
 * unmount. Safe to call only when not already pending.
 */
async function ask(question) {
  if (conversation.pending) return;
  conversation.add({ role: 'user', text: question });

  // Known-offline: answer instantly instead of a doomed slow round-trip.
  if (conversation.available === false) {
    conversation.add({ role: 'notice',
      text: conversation.offlineReason || 'Investigations are unavailable.' });
    checkStatus();
    return;
  }

  const gen = conversation._generation;
  conversation.pending = true;
  conversation.startedAt = Date.now();
  conversation._emit();

  let msg;
  try {
    const resp = await api.investigate(question);
    if (resp && resp.error) {
      msg = { role: 'notice', text: resp.aborted
        ? 'The investigation is taking longer than expected and was stopped. ' +
          'On a low-memory machine the local model can be slow — try a ' +
          'simpler question, or a smaller/faster model.'
        : (resp.message || 'Something went wrong reaching the investigator.') };
    } else {
      const data = (resp && resp.data) || {};
      if (data.available === false) {
        conversation.available = false;
        conversation.offlineReason = data.reason || '';
        msg = { role: 'notice', text: data.reason || 'Investigations are unavailable.' };
      } else {
        // A real answer proves the model is up.
        conversation.available = true;
        msg = { role: 'answer', data };
      }
    }
  } catch (err) {
    msg = { role: 'notice', text: 'Something went wrong reaching the investigator.' };
  }

  conversation.pending = false;
  // If the user reset the chat while this was in flight, drop the stale answer
  // rather than appending it to a cleared thread.
  if (gen !== conversation._generation) { conversation._emit(); return; }
  conversation.add(msg);
}

async function checkStatus() {
  const resp = await api.getInvestigateStatus();
  const data = (resp && resp.data) || {};
  conversation.available = !!data.available;
  conversation.offlineReason = data.reason || '';
  conversation._emit();
}

export default class AskView {
  constructor(el) {
    this.el = el;
    this._unsub = null;
    this._ticker = null;
  }

  render() {
    this.el.innerHTML = `
      <div class="ask">
        <div class="ask__status" id="ask-status"></div>
        <div class="ask__thread" id="ask-thread"></div>
        <form class="ask__composer" id="ask-form">
          <input type="text" id="ask-input" class="ask__input" autocomplete="off"
                 placeholder="Ask a question about your network…" />
          <button type="submit" class="btn btn--primary" id="ask-send">Ask</button>
          <button type="button" class="btn" id="ask-reset" title="Clear this conversation">Reset</button>
        </form>
      </div>
    `;

    this.el.querySelector('#ask-form').addEventListener('submit', e => {
      e.preventDefault();
      const input = this.el.querySelector('#ask-input');
      const q = (input.value || '').trim();
      if (!q || conversation.pending) return;
      input.value = '';
      ask(q);
    });

    this.el.querySelector('#ask-reset').addEventListener('click', () => {
      conversation.reset();
    });

    // Re-render whenever the store changes — including while this view was
    // unmounted and an answer arrived in the background.
    this._unsub = conversation.subscribe(() => this._paint());
    this._paint();

    if (conversation.available === null) checkStatus();
  }

  destroy() {
    if (this._unsub) { this._unsub(); this._unsub = null; }
    this._stopTicker();
    // NB: the in-flight investigation is intentionally left running.
  }

  /* ── rendering (pure function of the store) ─────────────── */

  _paint() {
    const thread = this.el.querySelector('#ask-thread');
    if (!thread) return;                     // view was torn down mid-update
    thread.replaceChildren();

    if (!conversation.messages.length && !conversation.pending) {
      thread.appendChild(this._intro());
    }
    for (const m of conversation.messages) {
      if (m.role === 'user') thread.appendChild(this._userRow(m.text));
      else if (m.role === 'answer') thread.appendChild(this._answerRow(m.data));
      else thread.appendChild(this._noticeRow(m.text));
    }
    if (conversation.pending) thread.appendChild(this._thinkingRow());

    this._paintStatus();
    this._paintControls();
    thread.scrollTop = thread.scrollHeight;
  }

  _paintStatus() {
    const el = this.el.querySelector('#ask-status');
    if (!el) return;
    if (conversation.available === false) {
      el.className = 'ask__status ask__status--off';
      el.textContent = conversation.offlineReason ||
        'No local model running. Install Ollama and run `ollama pull llama3.2:3b` ' +
        'to enable Ask NetWatch — everything stays on this machine.';
    } else {
      // Ready/unknown: no banner, and never the model name.
      el.className = 'ask__status';
      el.textContent = '';
    }
  }

  _paintControls() {
    const send = this.el.querySelector('#ask-send');
    if (send) {
      send.disabled = conversation.pending;
      send.textContent = conversation.pending ? 'Thinking…' : 'Ask';
    }
    const reset = this.el.querySelector('#ask-reset');
    if (reset) reset.disabled = !conversation.messages.length && !conversation.pending;
  }

  _intro() {
    const wrap = document.createElement('div');
    wrap.className = 'ask__intro';
    const h = document.createElement('h3');
    h.textContent = 'Ask NetWatch';
    const p = document.createElement('p');
    p.textContent = 'Ask about your network in plain language. Answers are ' +
      'grounded in live data and show their sources.';
    const sugg = document.createElement('div');
    sugg.className = 'ask__suggestions';
    for (const s of SUGGESTIONS) {
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'ask__suggestion';
      chip.textContent = s;
      chip.addEventListener('click', () => { if (!conversation.pending) ask(s); });
      sugg.appendChild(chip);
    }
    wrap.append(h, p, sugg);
    return wrap;
  }

  _userRow(text) {
    const row = document.createElement('div');
    row.className = 'ask-msg ask-msg--user';
    const bubble = document.createElement('div');
    bubble.className = 'ask-msg__bubble';
    bubble.textContent = text;
    row.appendChild(bubble);
    return row;
  }

  _noticeRow(text) {
    const row = document.createElement('div');
    row.className = 'ask-msg ask-msg--notice';
    const bubble = document.createElement('div');
    bubble.className = 'ask-msg__bubble ask-msg__bubble--notice';
    bubble.textContent = text;
    row.appendChild(bubble);
    return row;
  }

  _thinkingRow() {
    const row = document.createElement('div');
    row.className = 'ask-msg ask-msg--assistant';
    const bubble = document.createElement('div');
    bubble.className = 'ask-msg__bubble ask-msg__bubble--thinking';
    row.appendChild(bubble);

    // Elapsed time is derived from the store's startedAt, so it stays correct
    // across a remount (the investigation kept running while we were away).
    const paint = () => {
      const secs = Math.round((Date.now() - conversation.startedAt) / 1000);
      let label = 'Investigating…';
      if (secs >= 5) label = `Investigating… ${secs}s`;
      if (secs >= 30) {
        label = `Investigating… ${secs}s — retrieving and reasoning over live ` +
                'data; slower machines can take a minute or two.';
      }
      bubble.textContent = label;
    };
    paint();
    this._startTicker(paint);
    return row;
  }

  _startTicker(fn) {
    this._stopTicker();
    this._ticker = setInterval(() => {
      if (!conversation.pending) { this._stopTicker(); return; }
      fn();
    }, 1000);
  }

  _stopTicker() {
    if (this._ticker) { clearInterval(this._ticker); this._ticker = null; }
  }

  _answerRow(data) {
    const row = document.createElement('div');
    row.className = 'ask-msg ask-msg--assistant';

    const bubble = document.createElement('div');
    bubble.className = 'ask-msg__bubble';

    const answer = document.createElement('div');
    answer.className = 'ask-msg__answer';
    answer.textContent = (data && data.answer) || '(no answer)';
    bubble.appendChild(answer);

    const citations = Array.isArray(data && data.citations) ? data.citations : [];
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

    const calls = Array.isArray(data && data.tool_calls) ? data.tool_calls : [];
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
        line.textContent = `${call.tool}(${JSON.stringify(call.params || {})})`;
        details.appendChild(line);
      }
      bubble.appendChild(details);
    }

    row.appendChild(bubble);
    return row;
  }
}
