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

  const customAccessEnabled = document.body.dataset.customAccessEnabled === "true";
  const accessEditorMarkup = () => `<label class="form-label">Network access</label><select class="form-select js-access-mode" name="access_mode"><option value="full">Full VPN access</option><option value="custom" ${customAccessEnabled ? "" : "disabled"}>Custom destinations and services</option></select><input type="hidden" name="access_rules" value="[]" class="js-access-rules"><div class="access-custom mt-3" hidden><div class="js-access-rule-list"></div><button class="btn btn-outline-primary btn-sm js-add-access-rule" type="button">Add destination</button><small class="form-hint d-block mt-2">The policy is applied on the next VPN connection. Routes shown by the client are not the security boundary.</small></div>`;
  const portText = (ports) => (ports || []).map(([start, end]) => start === end ? String(start) : `${start}-${end}`).join(", ");
  const accessRuleMarkup = (rule = {}) => `<div class="access-rule"><div><label class="form-label">Destination</label><input class="form-control js-rule-destination" placeholder="192.0.2.50 or 192.0.2.0/24" value="${escapeHtml(rule.destination || "")}" maxlength="43" required></div><div><label class="form-label">Protocol</label><select class="form-select js-rule-protocol"><option value="tcp" ${rule.protocol === "tcp" || !rule.protocol ? "selected" : ""}>TCP</option><option value="udp" ${rule.protocol === "udp" ? "selected" : ""}>UDP</option><option value="icmp" ${rule.protocol === "icmp" ? "selected" : ""}>ICMP</option><option value="ip" ${rule.protocol === "ip" ? "selected" : ""}>Any IP</option></select></div><div><label class="form-label">Ports</label><input class="form-control js-rule-ports" placeholder="Required: 443, 8000-8010" value="${escapeHtml(portText(rule.ports))}" maxlength="180"></div><button type="button" class="btn btn-ghost-danger js-remove-access-rule" aria-label="Remove rule">Remove</button></div>`;
  const initializeAccessEditor = (editor, initialPolicy = {mode: "full", rules: []}, allowCustom = customAccessEnabled) => {
    if (!editor) return;
    const mode = editor.querySelector(".js-access-mode");
    const hidden = editor.querySelector(".js-access-rules");
    const custom = editor.querySelector(".access-custom");
    const list = editor.querySelector(".js-access-rule-list");
    const add = editor.querySelector(".js-add-access-rule");
    const normalized = initialPolicy?.mode === "custom" ? initialPolicy : {mode: "full", rules: []};
    mode.querySelector('option[value="custom"]').disabled = !allowCustom;
    mode.value = normalized.mode;
    const updatePortField = (row) => {
      const protocol = row.querySelector(".js-rule-protocol").value;
      const ports = row.querySelector(".js-rule-ports");
      const supportsPorts = protocol === "tcp" || protocol === "udp";
      ports.disabled = !supportsPorts;
      ports.required = supportsPorts;
      if (!supportsPorts) ports.value = "";
    };
    const bindRow = (row) => {
      row.querySelector(".js-rule-protocol").addEventListener("change", () => updatePortField(row));
      row.querySelector(".js-remove-access-rule").addEventListener("click", () => row.remove());
      updatePortField(row);
    };
    const appendRule = (rule = {}) => {
      list.insertAdjacentHTML("beforeend", accessRuleMarkup(rule));
      bindRow(list.lastElementChild);
    };
    (normalized.rules || []).forEach(appendRule);
    const updateMode = () => {
      const restricted = mode.value === "custom";
      custom.hidden = !restricted;
      if (restricted && !list.children.length) appendRule();
      list.querySelectorAll("input, select").forEach((input) => { input.disabled = !restricted; });
      if (restricted) list.querySelectorAll(".access-rule").forEach(updatePortField);
    };
    const serialize = () => {
      if (mode.value !== "custom") {
        hidden.value = "[]";
        return;
      }
      const rules = [...list.querySelectorAll(".access-rule")].map((row) => ({
        destination: row.querySelector(".js-rule-destination").value.trim(),
        protocol: row.querySelector(".js-rule-protocol").value,
        ports: row.querySelector(".js-rule-ports").disabled ? "" : row.querySelector(".js-rule-ports").value.trim(),
      }));
      hidden.value = JSON.stringify(rules);
    };
    mode.addEventListener("change", updateMode);
    add.addEventListener("click", () => appendRule());
    editor.closest("form")?.addEventListener("submit", serialize);
    updateMode();
  };
  document.querySelectorAll(".js-access-editor").forEach((editor) => {
    let policy = {mode: "full", rules: []};
    try { policy = JSON.parse(editor.dataset.initialPolicy || "{}"); } catch (_error) { /* server validation remains authoritative */ }
    initializeAccessEditor(editor, policy);
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
  document.querySelectorAll("[data-copy-target]").forEach((button) => {
    button.addEventListener("click", async () => {
      const target = document.getElementById(button.dataset.copyTarget);
      if (!target?.value) return;
      await navigator.clipboard.writeText(target.value);
      button.textContent = "Copied";
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
        field.innerHTML = `<label class="form-label" for="action-input">New username</label><input class="form-control" id="action-input" name="new_username" value="${user}" required maxlength="64" pattern="[a-z0-9][a-z0-9._@-]{0,63}" autocomplete="off">`;
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
      } else if (action === "credential") {
        title.textContent = `Protect ${user}'s stored password?`;
        description.textContent = "This replaces the legacy clear-text credential with an MS-CHAPv2-compatible NT hash. A backup is created and FreeRADIUS is validated before the change is accepted.";
        field.innerHTML = `<div class="change-summary"><span>Credential storage</span><strong>Legacy clear text → NT hash</strong></div>`;
        form.action = `/users/${encode(user)}/credential`;
        submit.textContent = "Migrate credential";
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
        description.textContent = requireDuo ? "Duo will be checked for an active, Push-capable device before the change." : "The password remains required. This exception applies only to this VPN integration.";
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
      } else if (action === "access") {
        let policy = {mode: "full", rules: []};
        try { policy = JSON.parse(data.accessPolicy || "{}"); } catch (_error) { /* fail closed in the helper */ }
        title.textContent = `Network access for ${user}`;
        const eligible = data.customAccessEligible !== "false";
        description.textContent = eligible ? "Full access keeps the current VPN reachability. Custom access permits only the listed destinations and services." : "This username is reserved for router-local fallback, so it must keep full access.";
        field.innerHTML = `<div class="js-access-editor">${accessEditorMarkup()}</div>`;
        initializeAccessEditor(field.querySelector(".js-access-editor"), policy, eligible && customAccessEnabled);
        form.action = `/users/${encode(user)}/access`;
        submit.textContent = "Save access policy";
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
        form.method = "post";
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
        const credentialAction = data.credentialScheme === "legacy-cleartext" ? `<button type="button" class="admin-action" data-modal-action="credential">Protect stored password<span>Migrate to an MS-CHAPv2-compatible NT hash</span></button>` : "";
        field.innerHTML = `<div class="admin-action-grid"><button type="button" class="admin-action" data-modal-action="access">Network access<span>${escapeHtml(data.accessSummary || "Full access")}</span></button><button type="button" class="admin-action" data-modal-action="rename">Rename user<span>Keep RADIUS and Duo aligned</span></button><button type="button" class="admin-action" data-modal-action="password">Reset VPN password<span>Generate or enter a new secret</span></button>${credentialAction}<button type="button" class="admin-action" data-modal-action="duo-enroll">${enrollmentLabel}<span>${enrollmentHint}</span></button><button type="button" class="admin-action" data-modal-action="duo">${duoLabel}<span>Change VPN second-factor enforcement</span></button><button type="button" class="admin-action" data-modal-action="panel">${panelLabel}<span>Separate console credential + Duo</span></button><button type="button" class="admin-action" data-modal-action="expiry">Set account expiry<span>Automatic access cutoff</span></button><button type="button" class="admin-action" data-modal-action="duo-check">Check Duo readiness<span>Enrollment and Push capability</span></button><button type="button" class="admin-action" data-modal-action="status">${statusLabel}<span>Change VPN access immediately</span></button><button type="button" class="admin-action admin-action-danger" data-modal-action="delete">Delete user<span>Remove the local credential</span></button></div>`;
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
