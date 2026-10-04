(() => {
  const root = document.querySelector('[data-docs-root]');
  if (!root) return;
  const buttons = [...root.querySelectorAll('[data-doc-topic]')];
  const panels = [...root.querySelectorAll('[data-doc-panel]')];
  const show = id => {
    buttons.forEach(btn => btn.classList.toggle('active', btn.dataset.docTopic === id));
    panels.forEach(panel => { panel.hidden = panel.dataset.docPanel !== id; });
    const url = new URL(window.location.href);
    url.hash = id;
    history.replaceState(null, '', url);
  };
  buttons.forEach(btn => btn.addEventListener('click', () => show(btn.dataset.docTopic)));
  const initial = decodeURIComponent(location.hash.replace(/^#/, ''));
  if (initial && panels.some(panel => panel.dataset.docPanel === initial)) show(initial);
})();
