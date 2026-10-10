(function () {
  var root = document.documentElement;

  function current() {
    return root.dataset.theme ||
      (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
  }

  function toggleTheme() {
    var next = current() === 'dark' ? 'light' : 'dark';
    root.dataset.theme = next;
    document.cookie = 'theme=' + next +
      '; path=/; max-age=31536000; samesite=lax; secure';
  }

  document.querySelectorAll('.theme-toggle').forEach(function (btn) {
    btn.addEventListener('click', toggleTheme);
  });
})();
