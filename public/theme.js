// Apply the saved theme and lightning setting before the first paint (kept out of app.js, which loads deferred).
try {
  const theme = JSON.parse(localStorage.getItem('vw:theme'));
  if (theme === 'light' || theme === 'dark') document.documentElement.dataset.theme = theme;
  if (JSON.parse(localStorage.getItem('vw:fx')) === false) document.documentElement.dataset.fx = 'off';
} catch { /* storage blocked: follow the OS setting */ }
