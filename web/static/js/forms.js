(() => {
  const explicitAttr = (el, name) => el && el.hasAttribute(name) ? el.getAttribute(name) : '';
  const normalizeMethod = value => (value || 'POST').toUpperCase();
  const isEN = window.ZentCalLang === 'en';

  document.addEventListener('submit', async event => {
    const form = event.target.closest('form[data-ajax]');
    if (!form) return;
    event.preventDefault();

    const submitter = event.submitter || form.querySelector('button[type="submit"],input[type="submit"],button:not([type])');
    const errBox = form.querySelector('[data-form-error]');
    if (errBox) {
      errBox.textContent = '';
      errBox.classList.remove('show');
    }

    // Resolve native submission semantics before disabling the submitter.
    // This prevents browser defaults on formAction/formMethod from overriding
    // the form and guarantees that all successful form controls are captured.
    const actionAttr = explicitAttr(submitter, 'formaction');
    const methodAttr = explicitAttr(submitter, 'formmethod');
    const enctypeAttr = explicitAttr(submitter, 'formenctype');
    const action = actionAttr || form.getAttribute('action') || location.href;
    const method = normalizeMethod(methodAttr || form.getAttribute('method') || 'POST');
    const enctype = (enctypeAttr || form.getAttribute('enctype') || 'application/x-www-form-urlencoded').toLowerCase();
    const formData = submitter ? new FormData(form, submitter) : new FormData(form);

    const oldHTML = submitter?.innerHTML;
    const oldValue = submitter instanceof HTMLInputElement ? submitter.value : null;
    if (submitter) {
      submitter.disabled = true;
      const loading = submitter.dataset.loadingText || (isEN ? 'Saving…' : 'Speichern…');
      if (submitter instanceof HTMLInputElement) submitter.value = loading;
      else submitter.innerHTML = `<span class="spinner"></span>${loading}`;
    }

    let keepLocked = false;
    try {
      const headers = {
        'X-CSRF-Token': window.ZentCal.csrf(),
        'Accept': 'application/json'
      };

      let body;
      let requestURL = action;
      if (method === 'GET' || method === 'HEAD') {
        const url = new URL(action, location.href);
        new URLSearchParams(formData).forEach((value, key) => url.searchParams.append(key, value));
        requestURL = url.toString();
      } else if (enctype === 'multipart/form-data') {
        body = formData;
      } else {
        body = new URLSearchParams(formData);
        headers['Content-Type'] = 'application/x-www-form-urlencoded;charset=UTF-8';
      }

      const res = await fetch(requestURL, { method, body, headers });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        const suffix = data.request_id ? ` · Request-ID: ${data.request_id}` : '';
        throw new Error((data.error || (isEN ? `Action failed (HTTP ${res.status}).` : `Aktion fehlgeschlagen (HTTP ${res.status}).`)) + suffix);
      }

      if (data.secret) {
        document.querySelector('#secret-message').textContent = data.message || '';
        document.querySelector('#secret-value').textContent = data.secret;
        const warning = document.querySelector('#secret-warning');
        if (warning) warning.textContent = data.secret_warning || (isEN ? 'This value will not be shown again after closing.' : 'Dieser Wert wird nach dem Schließen nicht erneut angezeigt.');
        window.ZentModal.open('secret-modal');
        const parent = form.closest('.modal');
        if (parent) window.ZentModal.close(parent);
        form.reset();
        if (data.reload_after_secret) {
          sessionStorage.setItem('zentcal-reload-after-secret', '1');
          if (form.dataset.returnModal) sessionStorage.setItem('zentcal-reopen-modal', form.dataset.returnModal);
        }
      }
      const reloadAfter = Number(data.reload_after_ms || 0);
      if (data.message && !data.secret && !data.reload && !reloadAfter) window.ZentCal.toast(data.message);
      if (reloadAfter > 0) {
        keepLocked = true;
        if (data.message) window.ZentCal.toast(data.message);
        const modal = form.closest('.modal');
        if (modal) {
          modal.dataset.busy = 'true';
          modal.querySelectorAll('[data-modal-close]').forEach(el => { el.disabled = true; });
        }
        setTimeout(() => location.reload(), Math.max(250, reloadAfter));
        return;
      }
      if (data.message && data.reload) sessionStorage.setItem('zentcal-flash', data.message);
      if (data.redirect) { location.href = data.redirect; return; }
      if (data.reload) { location.reload(); return; }
    } catch (err) {
      if (errBox) {
        errBox.textContent = err.message;
        errBox.classList.add('show');
      } else {
        window.ZentCal.toast(err.message, 'error');
      }
    } finally {
      if (!keepLocked && submitter && document.body.contains(submitter)) {
        submitter.disabled = false;
        if (submitter instanceof HTMLInputElement) submitter.value = oldValue;
        else submitter.innerHTML = oldHTML;
      }
    }
  });

  document.addEventListener('click', event => {
    if (!event.target.closest('[data-modal-close]')) return;
    const modal = event.target.closest('.modal');
    if (modal?.id === 'secret-modal' && sessionStorage.getItem('zentcal-reload-after-secret') === '1') {
      sessionStorage.removeItem('zentcal-reload-after-secret');
      location.reload();
    }
  });
})();
