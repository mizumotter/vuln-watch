// Apply the saved theme before the first paint (kept out of app.js, which loads deferred).
try {
  const theme = JSON.parse(localStorage.getItem('vw:theme'));
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
} catch { /* storage blocked: follow the OS setting */ }
