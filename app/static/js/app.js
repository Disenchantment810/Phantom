// PHANTOM progressive enhancement. Loaded deferred; no external dependencies.
// Confirmation prompts declared via data-confirm on destructive forms.
document.addEventListener("submit", (event) => {
  const form = event.target;
  if (form instanceof HTMLFormElement && form.dataset.confirm) {
    if (!window.confirm(form.dataset.confirm)) {
      event.preventDefault();
    }
  }
});
