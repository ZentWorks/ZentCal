(() => {
  const roots = [...document.querySelectorAll('.admin-api-docs-panel[data-api-base]')];
  if (!roots.length) return;

  const quoteShell = (value) => `'${String(value).replace(/'/g, `'"'"'`)}'`;
  const pretty = (value) => {
    try { return JSON.stringify(JSON.parse(value), null, 2); } catch (_) { return value; }
  };

  for (const root of roots) {
    const tokenInput = root.querySelector('[data-api-playground-token]');
    const navButtons = [...root.querySelectorAll('[data-api-doc]')];
    const panels = [...root.querySelectorAll('[data-api-panel]')];
    const apiBase = (root.dataset.apiBase || '/api/v1').replace(/\/$/, '');
    const tokenEnv = root.dataset.apiTokenEnv || 'ZENTCAL_API_TOKEN';
    const tokenMissing = root.dataset.apiTokenMissing || 'API Token fehlt.';

    function buildCurl(panel) {
      const method = panel.dataset.apiMethod || 'GET';
      const pathInput = panel.querySelector('[data-api-playground-path]');
      const bodyInput = panel.querySelector('[data-api-playground-body]');
      const path = (pathInput?.value || panel.dataset.apiPath || '').trim();
      const url = `${window.location.origin}${path}`;
      const lines = [`curl -X ${method} ${quoteShell(url)} \\`, `  -H 'Authorization: Bearer $${tokenEnv}'`];
      const body = bodyInput?.value.trim();
      if (body) {
        lines[lines.length - 1] += ' \\';
        lines.push(`  -H 'Content-Type: application/json' \\`);
        lines.push(`  --data ${quoteShell(body)}`);
      }
      return lines.join('\n');
    }

    function updateCurl(panel) {
      const code = panel.querySelector('[data-api-curl] code');
      if (code) code.textContent = buildCurl(panel);
    }

    function activate(id) {
      navButtons.forEach((button) => button.classList.toggle('active', button.dataset.apiDoc === id));
      panels.forEach((panel) => { panel.hidden = panel.dataset.apiPanel !== id; });
      const panel = panels.find((item) => item.dataset.apiPanel === id);
      if (panel) updateCurl(panel);
    }

    navButtons.forEach((button) => button.addEventListener('click', () => activate(button.dataset.apiDoc)));
    panels.forEach((panel) => {
      panel.querySelector('[data-api-playground-path]')?.addEventListener('input', () => updateCurl(panel));
      panel.querySelector('[data-api-playground-body]')?.addEventListener('input', () => updateCurl(panel));
      updateCurl(panel);
    });

    root.addEventListener('click', async (event) => {
      const copyTarget = event.target.closest('[data-copy-target]');
      if (copyTarget) {
        const el = document.getElementById(copyTarget.dataset.copyTarget);
        if (el) await navigator.clipboard.writeText(el.textContent || '');
        return;
      }
      const copyCurl = event.target.closest('[data-copy-curl]');
      if (copyCurl) {
        const panel = copyCurl.closest('[data-api-panel]');
        if (panel) await navigator.clipboard.writeText(buildCurl(panel));
        return;
      }
      const copyResponse = event.target.closest('[data-copy-playground-response]');
      if (copyResponse) {
        const panel = copyResponse.closest('[data-api-panel]');
        const response = panel?.querySelector('[data-api-response] code');
        if (response) await navigator.clipboard.writeText(response.textContent || '');
        return;
      }

      const send = event.target.closest('[data-api-send]');
      if (!send) return;
      const panel = send.closest('[data-api-panel]');
      if (!panel) return;

      const token = tokenInput?.value.trim() || '';
      const method = panel.dataset.apiMethod || 'GET';
      const path = panel.querySelector('[data-api-playground-path]')?.value.trim() || '';
      const body = panel.querySelector('[data-api-playground-body]')?.value.trim() || '';
      const meta = panel.querySelector('[data-api-playground-meta]');
      const responseWrap = panel.querySelector('[data-api-response-wrap]');
      const responseCode = panel.querySelector('[data-api-response] code');

      if (!token) {
        if (meta) meta.textContent = tokenMissing;
        tokenInput?.focus();
        return;
      }
      let targetURL;
      try { targetURL = new URL(path, window.location.origin); } catch (_) {
        if (meta) meta.textContent = 'Ungültiger API-Pfad.';
        return;
      }
      const allowedPath = targetURL.pathname === apiBase || targetURL.pathname.startsWith(`${apiBase}/`);
      if (targetURL.origin !== window.location.origin || !allowedPath) {
        if (meta) meta.textContent = 'Nur Pfade dieser ZentCal API sind erlaubt.';
        return;
      }
      if (/[{}]/.test(path)) {
        if (meta) meta.textContent = 'Bitte zuerst alle Pfad-Parameter wie {id} ersetzen.';
        return;
      }
      if (body) {
        try { JSON.parse(body); } catch (err) {
          if (meta) meta.textContent = `Ungültiges JSON: ${err.message}`;
          return;
        }
      }
      if (panel.dataset.apiDestructive === 'true' && !window.confirm('Diesen Request wirklich ausführen?')) return;

      send.disabled = true;
      const oldText = send.textContent;
      send.textContent = 'Sende…';
      if (meta) meta.textContent = '';
      if (responseWrap) responseWrap.hidden = true;
      const started = performance.now();
      try {
        const headers = { Authorization: `Bearer ${token}`, Accept: 'application/json' };
        const options = { method, headers, credentials: 'same-origin', cache: 'no-store' };
        if (body && method !== 'GET' && method !== 'HEAD') {
          headers['Content-Type'] = 'application/json';
          options.body = body;
        }
        const response = await fetch(targetURL.pathname + targetURL.search, options);
        const text = await response.text();
        const elapsed = Math.round(performance.now() - started);
        if (meta) meta.textContent = `HTTP ${response.status} · ${elapsed} ms`;
        if (responseCode) responseCode.textContent = text ? pretty(text) : '(kein Inhalt)';
        if (responseWrap) responseWrap.hidden = false;
      } catch (err) {
        const elapsed = Math.round(performance.now() - started);
        if (meta) meta.textContent = `Fehler · ${elapsed} ms`;
        if (responseCode) responseCode.textContent = String(err?.message || err);
        if (responseWrap) responseWrap.hidden = false;
      } finally {
        send.disabled = false;
        send.textContent = oldText;
      }
    });
  }
})();
