// Apply saved theme before first paint to prevent FOUC
(function() {
  var t = localStorage.getItem('netwatch-theme') || 'dark';
  document.documentElement.setAttribute('data-theme', t);
})();
