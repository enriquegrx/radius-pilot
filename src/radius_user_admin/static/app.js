(() => {
  const encode = (value) => encodeURIComponent(value);
  const escapeHtml = (value) => String(value || "").replace(/[&<>'"]/g, (character) => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;"})[character]);
  const localDateTime = (value) => value ? new Date(value).toISOString().slice(0, 16) : "";

  document.querySelectorAll("dialog").forEach((dialog) => {
    dialog.querySelectorAll("[data-dialog-close]").forEach((button) => {
      button.addEventListener("click", () => dialog.close());
    });
    dialog.addEventListener("click", (event) => {
      if (event.target === dialog) dialog.close();
    });
    dialog.addEventListener("close", () => {
      dialog.querySelectorAll("[data-secret]").forEach((input) => {
        input.value = "";
        input.type = "password";
      });
    });
  });
  document.querySelectorAll("[data-dialog-open]").forEach((button) => {
    button.addEventListener("click", () => document.getElementById(button.dataset.dialogOpen)?.showModal());
  });

  const search = document.getElementById("user-search");
  const filter = document.getElementById("user-filter");
  const rows = [...document.querySelectorAll("[data-user-row]")];
  const empty = document.getElementById("no-filter-results");
  const applyFilters = () => {
    const query = search?.value.trim().toLowerCase() || "";
    const selected = filter?.value || "all";
    let visible = 0;
    rows.forEach((row) => {
      const matchesQuery = row.dataset.username.includes(query);
      const matchesFilter = selected === "all" || row.dataset.filterStatus === selected || row.dataset.filterDuo === selected;
      row.hidden = !(matchesQuery && matchesFilter);
      if (!row.hidden) visible += 1;
    });
    if (empty) empty.hidden = visible !== 0;
  };
  search?.addEventListener("input", applyFilters);
  filter?.addEventListener("change", applyFilters);

  document.querySelectorAll(".js-duo-mode").forEach((select) => {
    const form = select.closest("form");
    const fields = form?.querySelector(".duo-bypass-fields");
    const reason = fields?.querySelector('[name="duo_bypass_reason"]');
    const update = () => {
      const passwordOnly = select.value === "false";
      if (fields) fields.hidden = !passwordOnly;
      if (reason) reason.required = passwordOnly;
    };
    select.addEventListener("change", update);
    update();
  });
  document.querySelectorAll(".js-panel-role").forEach((select) => {
    const form = select.closest("form");
    const fields = form?.querySelector(".panel-password-fields");
    const password = fields?.querySelector('[name="panel_password"]');
    const update = () => {
      const enabled = select.value === "true";
      if (fields) fields.hidden = !enabled;
      if (password) password.required = enabled;
    };
    select.addEventListener("change", update);
    update();
  });

  const generatePassword = () => {
    const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#%+-_";
    const values = new Uint32Array(24);
    crypto.getRandomValues(values);
    return [...values].map((value) => alphabet[value % alphabet.length]).join("");
  };
  document.querySelectorAll(".js-generate-password").forEach((button) => {
    button.addEventListener("click", () => {
      const target = document.getElementById(button.dataset.target);
      if (!target) return;
      target.value = generatePassword();
      target.type = "text";
      target.focus();
    });
  });
  document.querySelectorAll(".js-copy-password").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.target);
      if (!target?.value) return;
      await navigator.clipboard.writeText(target.value);
      const original = button.textContent;
      button.textContent = "Copied";
      setTimeout(() => { button.textContent = original; }, 1500);
    });
  });

  const modal = document.getElementById("action-modal");
  const form = document.getElementById("action-form");
  const title = document.getElementById("action-title");
  const description = document.getElementById("action-description");
  const field = document.getElementById("action-field");
  const submit = document.getElementById("action-submit");
  const cancel = document.getElementById("action-cancel");
  if (modal && form && title && description && field && submit && cancel) {
    const passwordInput = () => `<label class="form-label" for="action-input">New password</label><div class="input-group"><input class="form-control" id="action-input" name="password" type="password" data-secret required minlength="14" maxlength="128" autocomplete="new-password"><button class="btn btn-outline-secondary js-action-generate" type="button">Generate</button><button class="btn btn-outline-secondary js-action-copy" type="button">Copy</button></div><small class="form-hint">Shown only while this dialog is open.</small>`;
    const configureAction = (action, data) => {
      const user = data.user;
      submit.hidden = false;
      submit.className = "btn btn-primary";
      form.method = "post";
      cancel.textContent = "Cancel";
      field.innerHTML = "";
      if (action === "rename") {
        title.textContent = `Rename ${user}`;
        description.textContent = "Duo readiness will be checked before the renamed account is used.";
        field.innerHTML = `<label class="form-label" for="action-input">New username</label><input class="form-control" id="action-input" name="new_username" value="${user}" required maxlength="64" pattern="[a-z0-9][a-z0-9._-]{0,63}" autocomplete="off">`;
        form.action = `/users/${encode(user)}/rename`;
        submit.textContent = "Rename user";
      } else if (action === "password") {
        title.textContent = `Reset ${user}'s password`;
        description.textContent = "The previous password will be replaced and is never displayed.";
        field.innerHTML = passwordInput();
        form.action = `/users/${encode(user)}/password`;
        submit.textContent = "Reset password";
        const input = document.getElementById("action-input");
        field.querySelector(".js-action-generate").addEventListener("click", () => { input.value = generatePassword(); input.type = "text"; });
        field.querySelector(".js-action-copy").addEventListener("click", async (event) => { if (input.value) { await navigator.clipboard.writeText(input.value); event.currentTarget.textContent = "Copied"; } });
      } else if (action === "status") {
        const enable = data.enabled !== "true";
        title.textContent = `${enable ? "Unblock" : "Block"} ${user}?`;
        description.textContent = enable ? "VPN access will be restored." : "The user will be denied before Duo authentication.";
        field.innerHTML = `<div class="change-summary"><span>Access</span><strong>${enable ? "Blocked → Enabled" : "Enabled → Blocked"}</strong></div><input type="hidden" name="enabled" value="${enable}">`;
        form.action = `/users/${encode(user)}/status`;
        submit.textContent = enable ? "Unblock user" : "Block user";
        if (!enable) submit.className = "btn btn-warning";
      } else if (action === "duo") {
        const requireDuo = data.duoRequired !== "true";
        title.textContent = `${requireDuo ? "Require Duo Push" : "Use password only"} for ${user}?`;
        description.textContent = requireDuo ? "Duo will be checked for an active, Push-capable device before the change." : "The password remains required. This exception applies only to the Example Organization VPN.";
        field.innerHTML = `<div class="change-summary mb-3"><span>Authentication</span><strong>${requireDuo ? "Password only → Duo Push" : "Duo Push → Password only"}</strong></div><input type="hidden" name="duo_required" value="${requireDuo}">${requireDuo ? "" : `<div class="mb-3"><label class="form-label" for="bypass-reason">Reason for exception</label><input class="form-control" id="bypass-reason" name="duo_bypass_reason" maxlength="160" required value="${escapeHtml(data.bypassReason)}"></div><div><label class="form-label" for="bypass-until">Return to Duo automatically</label><input class="form-control" id="bypass-until" name="duo_bypass_until" type="datetime-local" value="${localDateTime(data.bypassUntil)}"><small class="form-hint">Recommended for every password-only exception.</small></div>`}`;
        form.action = `/users/${encode(user)}/duo`;
        submit.textContent = requireDuo ? "Verify and require Duo" : "Create exception";
        if (!requireDuo) submit.className = "btn btn-warning";
      } else if (action === "expiry") {
        title.textContent = `Set expiry for ${user}`;
        description.textContent = "The account is blocked automatically when this time is reached.";
        field.innerHTML = `<label class="form-label" for="action-input">Account expiry</label><input class="form-control" id="action-input" name="expires_at" type="datetime-local" value="${localDateTime(data.expiresAt)}"><small class="form-hint">Leave empty to remove the expiry.</small>`;
        form.action = `/users/${encode(user)}/expiry`;
        submit.textContent = "Save expiry";
      } else if (action === "duo-check") {
        title.textContent = `Check Duo readiness for ${user}?`;
        description.textContent = "This checks enrollment and Push capability. It does not send a Push.";
        field.innerHTML = "";
        form.action = `/users/${encode(user)}/duo-check`;
        submit.textContent = "Check Duo";
      } else if (action === "duo-enroll") {
        const activeEnrollment = data.duoEnrollmentActive === "true";
        title.textContent = `${activeEnrollment ? "View" : "Create"} Duo enrollment for ${user}?`;
        description.textContent = activeEnrollment ? "The current activation is still valid." : "Duo will create the user and issue a QR code valid for seven days.";
        field.innerHTML = `<div class="change-summary"><span>Second factor</span><strong>${activeEnrollment ? "Active Duo Mobile QR" : "Create Duo Mobile activation"}</strong></div>`;
        form.action = `/users/${encode(user)}/duo-${activeEnrollment ? "enrollment" : "enroll"}`;
        form.method = activeEnrollment ? "get" : "post";
        submit.textContent = activeEnrollment ? "View QR" : "Create enrollment";
      } else if (action === "panel") {
        const enable = data.panelAccess !== "true";
        title.textContent = `${enable ? "Grant" : "Revoke"} panel access for ${user}?`;
        description.textContent = enable ? "This creates a separate console credential and requires Duo Push at every panel sign-in." : "The VPN account remains active. Revocation takes effect on the next request.";
        field.innerHTML = `<div class="change-summary mb-3"><span>Panel role</span><strong>${enable ? "VPN user → Panel administrator" : "Panel administrator → VPN user"}</strong></div><input type="hidden" name="enabled" value="${enable}">${enable ? `<label class="form-label" for="action-input">New console password</label><div class="input-group"><input class="form-control" id="action-input" name="panel_password" type="password" data-secret required minlength="14" maxlength="128" autocomplete="new-password"><button class="btn btn-outline-secondary js-action-generate" type="button">Generate</button><button class="btn btn-outline-secondary js-action-copy" type="button">Copy</button></div><small class="form-hint">Use a different password from the VPN credential.</small>` : ""}`;
        form.action = `/users/${encode(user)}/panel`;
        submit.textContent = enable ? "Verify Duo and grant access" : "Revoke panel access";
        if (!enable) submit.className = "btn btn-warning";
        if (enable) {
          const input = document.getElementById("action-input");
          field.querySelector(".js-action-generate").addEventListener("click", () => { input.value = generatePassword(); input.type = "text"; });
          field.querySelector(".js-action-copy").addEventListener("click", async (event) => { if (input.value) { await navigator.clipboard.writeText(input.value); event.currentTarget.textContent = "Copied"; } });
        }
      } else {
        title.textContent = `Delete ${user}?`;
        description.textContent = "This permanently removes the local VPN credential. The Duo account is not deleted.";
        field.innerHTML = `<div class="change-summary danger"><span>User</span><strong>${user}</strong></div>`;
        form.action = `/users/${encode(user)}/delete`;
        submit.textContent = "Delete user";
        submit.className = "btn btn-danger";
      }
      requestAnimationFrame(() => document.getElementById("action-input")?.focus());
    };

    document.querySelectorAll(".js-manage").forEach((button) => {
      button.addEventListener("click", () => {
        const data = {...button.dataset};
        title.textContent = `Manage ${data.user}`;
        description.textContent = "Choose an account action.";
        submit.hidden = true;
        cancel.textContent = "Close";
        form.removeAttribute("action");
        const statusLabel = data.enabled === "true" ? "Block user" : "Unblock user";
        const duoLabel = data.duoRequired === "true" ? "Use password only" : "Require Duo Push";
        const panelLabel = data.panelAccess === "true" ? "Revoke panel access" : "Grant panel access";
        const enrollmentLabel = data.duoEnrollmentActive === "true" ? "View Duo enrollment" : "Enroll in Duo";
        const enrollmentHint = data.duoEnrollmentActive === "true" ? "Open the active QR and mobile link" : "Create a seven-day QR activation";
        field.innerHTML = `<div class="admin-action-grid"><button type="button" class="admin-action" data-modal-action="rename">Rename user<span>Keep RADIUS and Duo aligned</span></button><button type="button" class="admin-action" data-modal-action="password">Reset VPN password<span>Generate or enter a new secret</span></button><button type="button" class="admin-action" data-modal-action="duo-enroll">${enrollmentLabel}<span>${enrollmentHint}</span></button><button type="button" class="admin-action" data-modal-action="duo">${duoLabel}<span>Change VPN second-factor enforcement</span></button><button type="button" class="admin-action" data-modal-action="panel">${panelLabel}<span>Separate console credential + Duo</span></button><button type="button" class="admin-action" data-modal-action="expiry">Set account expiry<span>Automatic access cutoff</span></button><button type="button" class="admin-action" data-modal-action="duo-check">Check Duo readiness<span>Enrollment and Push capability</span></button><button type="button" class="admin-action" data-modal-action="status">${statusLabel}<span>Change VPN access immediately</span></button><button type="button" class="admin-action admin-action-danger" data-modal-action="delete">Delete user<span>Remove the local credential</span></button></div>`;
        field.querySelectorAll("[data-modal-action]").forEach((actionButton) => actionButton.addEventListener("click", () => configureAction(actionButton.dataset.modalAction, data)));
        modal.showModal();
      });
    });
  }

  const restoreModal = document.getElementById("restore-modal");
  const restoreForm = document.getElementById("restore-form");
  const restoreName = document.getElementById("restore-name");
  const restoreConfirm = document.getElementById("restore-confirm");
  document.querySelectorAll(".js-restore").forEach((button) => {
    button.addEventListener("click", () => {
      const backup = button.dataset.backup;
      restoreForm.action = `/backups/${encode(backup)}/restore`;
      restoreName.textContent = backup;
      restoreConfirm.value = "";
      restoreModal.showModal();
      requestAnimationFrame(() => restoreConfirm.focus());
    });
  });
})();
