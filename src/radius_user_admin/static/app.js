(() => {
  const modalElement = document.getElementById("action-modal");
  const modal = modalElement ? new bootstrap.Modal(modalElement) : null;
  const form = document.getElementById("action-form");
  const title = document.getElementById("action-title");
  const description = document.getElementById("action-description");
  const field = document.getElementById("action-field");
  const submit = document.getElementById("action-submit");
  const cancel = document.getElementById("action-cancel");

  const input = (label, name, type, value = "") =>
    `<label class="form-label" for="action-input">${label}</label>` +
    `<input class="form-control" id="action-input" name="${name}" type="${type}" value="${value}" required ` +
    `${type === "password" ? 'minlength="14" maxlength="128" autocomplete="new-password"' : 'maxlength="64" pattern="[a-z0-9][a-z0-9._-]{0,63}" autocomplete="off"'}>`;

  const configureAction = (action, user, enabled) => {
    const encoded = encodeURIComponent(user);
    submit.hidden = false;
    submit.className = "btn btn-primary";
    cancel.textContent = "Cancel";
    field.innerHTML = "";
    if (action === "rename") {
      title.textContent = `Rename ${user}`;
      description.textContent = "Remember to keep the Duo username identical.";
      field.innerHTML = input("New username", "new_username", "text", user);
      form.action = `/users/${encoded}/rename`;
      submit.textContent = "Rename user";
    } else if (action === "password") {
      title.textContent = `Reset ${user}'s password`;
      description.textContent = "The previous password is not displayed and will be replaced.";
      field.innerHTML = input("New password", "password", "password");
      form.action = `/users/${encoded}/password`;
      submit.textContent = "Reset password";
    } else if (action === "status") {
      const verb = enabled === "true" ? "Unblock" : "Block";
      title.textContent = `${verb} ${user}?`;
      description.textContent = enabled === "true" ? "The user will be able to authenticate again." : "Authentication will stop before Duo Push.";
      field.innerHTML = `<input type="hidden" name="enabled" value="${enabled}">`;
      form.action = `/users/${encoded}/status`;
      submit.textContent = `${verb} user`;
      if (enabled !== "true") submit.className = "btn btn-warning";
    } else {
      title.textContent = `Delete ${user}?`;
      description.textContent = "This permanently removes the local VPN credential. The Duo account is not deleted.";
      form.action = `/users/${encoded}/delete`;
      submit.textContent = "Delete user";
      submit.className = "btn btn-danger";
    }
    requestAnimationFrame(() => document.getElementById("action-input")?.focus());
  };

  document.querySelectorAll(".js-manage").forEach((button) => {
    button.addEventListener("click", () => {
      const user = button.dataset.user;
      const nextEnabled = button.dataset.enabled === "true" ? "false" : "true";
      const statusLabel = nextEnabled === "true" ? "Unblock user" : "Block user";
      title.textContent = `Manage ${user}`;
      description.textContent = "Choose an account action.";
      submit.hidden = true;
      cancel.textContent = "Close";
      form.removeAttribute("action");
      field.innerHTML = `
        <div class="admin-action-grid">
          <button type="button" class="admin-action" data-modal-action="rename">Rename user<span>Keep Duo and RADIUS aligned</span></button>
          <button type="button" class="admin-action" data-modal-action="password">Reset password<span>Replace the current secret</span></button>
          <button type="button" class="admin-action" data-modal-action="status">${statusLabel}<span>${nextEnabled === "true" ? "Restore VPN access" : "Stop access before Duo"}</span></button>
          <button type="button" class="admin-action admin-action-danger" data-modal-action="delete">Delete user<span>Remove the local credential</span></button>
        </div>`;
      field.querySelectorAll("[data-modal-action]").forEach((actionButton) => {
        actionButton.addEventListener("click", () => configureAction(actionButton.dataset.modalAction, user, nextEnabled));
      });
      modal.show();
    });
  });
})();
