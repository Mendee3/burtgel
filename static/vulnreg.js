/* VulnReg shared client helpers: API, toasts, confirm, combobox, register/edit form. */
(function () {
  "use strict";
  var BOOT = window.VR_BOOT || {};
  var VR = window.VR = { boot: BOOT };
  var BASE = "/registry/vulnerabilities";
  VR.BASE = BASE;

  // ---------- Formatting ----------
  VR.esc = function (s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  };
  var esc = VR.esc;
  VR.SEV = {
    critical: "Critical", high: "High", medium: "Medium", low: "Low", none: "None", "": "Үнэлээгүй"
  };
  VR.STATUS = {
    "new": "Шинэ", returned: "Буцаасан", assigned: "Хариуцагч томилсон", under_assessment: "Үнэлгээ хийгдэж буй",
    not_affected: "Нөлөөлөөгүй – Хаагдсан", risk_assessment: "Эрсдэлийн үнэлгээ", pending_cto: "CTO-ийн зөвшөөрөл хүлээж буй",
    accepted: "Эрсдэл хүлээн зөвшөөрсөн", transferred: "Шилжүүлсэн – Хаагдсан", avoidance: "Зайлсхийх (систем зогсоох)",
    remediation: "Засвар хийгдэж буй", verification: "Баталгаажуулалт", temp_mitigation: "Түр хамгаалалт", closed: "Хаагдсан"
  };
  VR.DEADLINE = { overdue: "Хугацаа хэтэрсэн", soon: "Хугацаа дөхсөн", ontrack: "Хугацаандаа", none: "Хугацаагүй" };
  VR.sevHtml = function (sev, cvss) {
    sev = VR.SEV.hasOwnProperty(sev) ? sev : "";
    var num = cvss != null ? ' <span class="cvss-num">' + Number(cvss).toFixed(1) + "</span>" : "";
    return '<span class="sev"><span class="dot ' + (sev || "unrated") + '" aria-hidden="true"></span>' + esc(VR.SEV[sev]) + num + "</span>";
  };
  VR.sevPill = function (sev) {
    sev = VR.SEV.hasOwnProperty(sev) ? sev : "";
    return '<span class="pill sev-' + (sev || "none") + '">' + esc(VR.SEV[sev]) + "</span>";
  };
  VR.statusHtml = function (st) {
    return '<span class="st st-' + esc(st) + '">' + esc(VR.STATUS[st] || st) + "</span>";
  };
  VR.deadlineText = function (dl) {
    if (!dl) return "";
    if (dl.kind === "overdue") return (-dl.days) + " хоног хэтэрсэн";
    if (dl.kind === "soon") return dl.days === 0 ? "Өнөөдөр дуусна" : dl.days + " хоног үлдсэн";
    if (dl.kind === "ontrack") return dl.days + " хоног үлдсэн";
    if (dl.kind === "none") return "Хугацаагүй";
    return "Шийдвэрлэсэн";
  };
  VR.deadlineHtml = function (dl) {
    return '<span class="dl-ind dl-' + esc(dl.kind) + '">' + esc(VR.deadlineText(dl)) + "</span>";
  };
  VR.fmtDateTime = function (iso) {
    if (!iso) return "—";
    var m = /^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})/.exec(iso);
    return m ? m[1] + " " + m[2] : iso;
  };
  VR.fmtSize = function (n) {
    if (n < 1024) return n + " B";
    if (n < 1048576) return (n / 1024).toFixed(1) + " KB";
    return (n / 1048576).toFixed(1) + " MB";
  };
  VR.todayIso = (function () {
    var d = new Date();
    return d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0");
  })();
  VR.addDays = function (iso, n) {
    var p = iso.split("-"), d = new Date(Date.UTC(+p[0], +p[1] - 1, +p[2] + n));
    return d.toISOString().slice(0, 10);
  };
  // Mirrors cvss_severity() in app.py using the SLA policy from Settings (the server value is authoritative).
  VR.SLA_DEFAULT = { critical: { min: 9, days: 5 }, high: { min: 7, days: 30 }, medium: { min: 4, days: 60 }, low: { min: 0.1, days: 90 } };
  VR.SEV_COLOR = { critical: "#C62828", high: "#E8710A", medium: "#E5B700", low: "#98A2B3" };
  VR.cvssRating = function (v, sla) {
    sla = sla || BOOT.sla || VR.SLA_DEFAULT;
    var levels = ["critical", "high", "medium", "low"];
    for (var i = 0; i < levels.length; i++) {
      var k = levels[i];
      if (v >= sla[k].min - 1e-9) return { key: k, color: VR.SEV_COLOR[k], days: sla[k].days };
    }
    return { key: "none", color: "#98A2B3", days: null };
  };

  // ---------- API ----------
  VR.api = function (url, opts) {
    opts = opts || {};
    var init = { credentials: "same-origin", headers: { "Accept": "application/json" } };
    if (opts.form) {
      init.method = "POST";
      if (opts.form instanceof FormData) {
        opts.form.set("_csrf", BOOT.csrf);
        init.body = opts.form;
      } else {
        var p = new URLSearchParams();
        Object.keys(opts.form).forEach(function (k) {
          var v = opts.form[k];
          p.append(k, v == null ? "" : String(v));
        });
        p.set("_csrf", BOOT.csrf);
        init.body = p;
      }
    }
    return fetch(url, init).then(function (res) {
      if (res.redirected && /\/login/.test(res.url)) {
        return { ok: false, status: 401, data: { error: "Нэвтрэх хугацаа дууссан. Хуудсаа дахин ачаална уу." } };
      }
      var ct = res.headers.get("Content-Type") || "";
      if (ct.indexOf("application/json") === -1) {
        return { ok: false, status: res.status, data: { error: res.status === 403 ? "Хандах эрхгүй эсвэл хуудасны хугацаа дууссан. Дахин ачаална уу." : "Серверийн алдаа (" + res.status + ")." } };
      }
      return res.json().then(function (data) { return { ok: res.ok, status: res.status, data: data }; });
    }, function () {
      return { ok: false, status: 0, data: { error: "Сервертэй холбогдож чадсангүй. Сүлжээгээ шалгана уу." } };
    });
  };
  var optionsPromise = null;
  VR.options = function () {
    if (!optionsPromise) {
      optionsPromise = VR.api(BASE + "/api/options").then(function (r) {
        if (!r.ok) { optionsPromise = null; throw new Error(r.data.error); }
        return r.data;
      });
    }
    return optionsPromise;
  };

  // ---------- Toasts ----------
  VR.toast = function (msg, kind, extraHtml) {
    var host = document.getElementById("toasts");
    if (!host) {
      host = document.createElement("div");
      host.id = "toasts"; host.className = "toasts";
      host.setAttribute("role", "status"); host.setAttribute("aria-live", "polite");
      document.body.appendChild(host);
    }
    var t = document.createElement("div");
    t.className = "toast " + (kind || "ok");
    t.innerHTML = esc(msg) + (extraHtml || "");
    host.appendChild(t);
    setTimeout(function () { t.remove(); }, kind === "err" ? 7000 : 4500);
  };

  // ---------- Modals ----------
  VR.showModal = function (dlg, focusEl) {
    if (!dlg.isConnected) document.body.appendChild(dlg);
    if (typeof dlg.showModal === "function") dlg.showModal(); else dlg.setAttribute("open", "");
    document.body.classList.add("modal-open");
    dlg.addEventListener("close", function () {
      if (!document.querySelector("dialog[open]")) document.body.classList.remove("modal-open");
    });
    if (focusEl) setTimeout(function () { focusEl.focus(); }, 0);
  };
  VR.confirm = function (o) {
    return new Promise(function (resolve) {
      var dlg = document.createElement("dialog");
      dlg.className = "modal narrow";
      dlg.setAttribute("aria-labelledby", "cf-title");
      dlg.innerHTML =
        '<form method="dialog"><div class="m-head"><div><h2 id="cf-title">' + esc(o.title) + "</h2></div></div>" +
        '<div class="m-body"><p style="margin:0">' + esc(o.body) + "</p>" + (o.extraHtml || "") + "</div>" +
        '<div class="m-foot"><button type="button" class="btn-secondary" value="no" data-act="no">Болих</button>' +
        '<button type="button" class="' + (o.danger ? "btn-danger" : "btn-primary") + '" data-act="yes">' + esc(o.confirmLabel || "Тийм") + "</button></div></form>";
      var result = false;
      dlg.addEventListener("click", function (e) {
        var b = e.target.closest("[data-act]");
        if (!b) return;
        result = b.getAttribute("data-act") === "yes";
        if (result && o.collect) result = o.collect(dlg) || true;
        dlg.close();
      });
      dlg.addEventListener("close", function () { dlg.remove(); resolve(result); });
      VR.showModal(dlg, dlg.querySelector('[data-act="no"]'));
    });
  };

  VR.setErrors = function (root, fields) {
    Array.prototype.forEach.call(root.querySelectorAll("[data-err]"), function (n) { n.textContent = ""; });
    Array.prototype.forEach.call(root.querySelectorAll('[aria-invalid="true"]'), function (n) { n.removeAttribute("aria-invalid"); });
    var first = null;
    Object.keys(fields || {}).forEach(function (k) {
      var out = root.querySelector('[data-err="' + k + '"]');
      if (out) out.textContent = fields[k];
      var input = root.querySelector('[data-field="' + k + '"]') || root.querySelector('[name="' + k + '"]');
      if (input) {
        input.setAttribute("aria-invalid", "true");
        if (!first) first = input;
      }
    });
    if (first) first.focus();
    return !first;
  };

  // ---------- Combobox ----------
  // items: [{id, label, sub}]; hidden input stores the id.
  // opts.onCreate(query) adds a trailing "create new" option (opts.createLabel(query) gives its text).
  VR.combo = function (input, hidden, items, opts) {
    opts = opts || {};
    var wrap = input.parentNode;
    var list = document.createElement("ul");
    var listId = input.id + "-list";
    list.className = "combo-list"; list.id = listId; list.setAttribute("role", "listbox"); list.hidden = true;
    wrap.appendChild(list);
    var clear = document.createElement("button");
    clear.type = "button"; clear.className = "combo-clear"; clear.setAttribute("aria-label", "Арилгах");
    clear.innerHTML = '<svg class="ico" aria-hidden="true"><use href="#i-x"/></svg>';
    wrap.appendChild(clear);
    input.setAttribute("role", "combobox"); input.setAttribute("aria-autocomplete", "list");
    input.setAttribute("aria-expanded", "false"); input.setAttribute("aria-controls", listId);
    input.autocomplete = "off";
    var shown = [], active = -1;
    function byId(id) { for (var i = 0; i < items.length; i++) if (String(items[i].id) === String(id)) return items[i]; return null; }
    function sync() { clear.hidden = !hidden.value && !input.value; }
    function setValue(id, silent) {
      var it = id ? byId(id) : null;
      hidden.value = it ? it.id : "";
      input.value = it ? it.label : "";
      sync();
      if (!silent && opts.onChange) opts.onChange(it);
    }
    function close() { list.hidden = true; input.setAttribute("aria-expanded", "false"); active = -1; }
    function render() {
      var q = input.value.trim().toLowerCase();
      var cur = byId(hidden.value);
      if (cur && cur.label === input.value) q = "";
      shown = items.filter(function (it) {
        return !q || (it.label + " " + (it.sub || "") + " #" + it.id).toLowerCase().indexOf(q) !== -1;
      }).slice(0, 60);
      if (opts.onCreate) shown.push({ create: true, query: input.value.trim() && !(cur && cur.label === input.value) ? input.value.trim() : "" });
      if (active >= shown.length) active = shown.length - 1;
      var html = shown.map(function (it, i) {
        var a = '<li role="option" id="' + listId + "-" + i + '" data-i="' + i + '" aria-selected="' + (i === active) + '"';
        if (it.create) return a + ' class="create"><span><svg class="ico" aria-hidden="true"><use href="#i-plus"/></svg> ' +
          esc(opts.createLabel ? opts.createLabel(it.query) : "Шинээр нэмэх") + "</span></li>";
        return a + ">" + esc(it.label) + (it.sub ? "<small>" + esc(it.sub) + "</small>" : "") + "</li>";
      }).join("");
      if (!shown.length || (shown.length === 1 && shown[0].create)) html = '<li class="empty">Илэрц олдсонгүй</li>' + html;
      list.innerHTML = html;
      list.hidden = false; input.setAttribute("aria-expanded", "true");
      if (active >= 0) input.setAttribute("aria-activedescendant", listId + "-" + active);
      else input.removeAttribute("aria-activedescendant");
    }
    input.addEventListener("focus", function () { active = -1; render(); });
    input.addEventListener("input", function () { active = 0; render(); sync(); });
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); if (list.hidden) render(); active = Math.min(active + 1, shown.length - 1); render(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); active = Math.max(active - 1, 0); render(); }
      else if (e.key === "Enter") { if (!list.hidden && shown[active]) { e.preventDefault(); pick(shown[active]); } }
      else if (e.key === "Escape") { if (!list.hidden) { e.preventDefault(); e.stopPropagation(); close(); } }
    });
    list.addEventListener("mousedown", function (e) {
      var li = e.target.closest("li[data-i]");
      if (!li) return;
      e.preventDefault();
      pick(shown[+li.getAttribute("data-i")]);
    });
    function pick(it) {
      close();
      if (it.create) { opts.onCreate(it.query); return; }
      setValue(it.id);
    }
    function addItem(it) { items.push(it); }
    input.addEventListener("blur", function () {
      setTimeout(function () {
        close();
        var cur = byId(hidden.value);
        if (!input.value.trim()) { if (hidden.value) setValue(""); }
        else if (!cur || cur.label !== input.value) setValue(hidden.value, true);
      }, 120);
    });
    clear.addEventListener("click", function () { setValue(""); input.focus(); });
    sync();
    return { setValue: setValue, addItem: addItem, get: function () { return hidden.value; }, item: function () { return byId(hidden.value); } };
  };

  // ---------- Shell ----------
  // Sidebar: always collapsed to the icon rail; expands over the page while hovered (or focused by keyboard).
  function initSidebar(shell) {
    var sidebar = shell && shell.querySelector(".sidebar");
    if (!sidebar) return;
    var narrow = window.matchMedia ? window.matchMedia("(max-width: 900px)") : { matches: false };
    var peeking = false, timer = null;
    function apply() {
      shell.classList.toggle("collapsed", !peeking);
      shell.classList.toggle("peek", peeking);
    }
    function peek(on, delay) {
      clearTimeout(timer);
      if (narrow.matches) { peeking = false; apply(); return; }
      timer = setTimeout(function () { if (peeking !== on) { peeking = on; apply(); } }, delay);
    }
    sidebar.addEventListener("mouseenter", function () { peek(true, 80); });
    sidebar.addEventListener("mouseleave", function () { if (!sidebar.contains(document.activeElement)) peek(false, 200); });
    sidebar.addEventListener("focusin", function () { peek(true, 0); });
    sidebar.addEventListener("focusout", function (e) { if (!sidebar.contains(e.relatedTarget) && !sidebar.matches(":hover")) peek(false, 0); });
    apply();
  }
  VR.initShell = function () {
    initSidebar(document.getElementById("shell"));
  };

  // Simple popup menu: trigger[aria-controls] toggles a .menu element.
  VR.menu = function (trigger, menu) {
    function close() { menu.hidden = true; trigger.setAttribute("aria-expanded", "false"); }
    trigger.setAttribute("aria-haspopup", "menu"); trigger.setAttribute("aria-expanded", "false");
    trigger.addEventListener("click", function (e) {
      e.stopPropagation();
      var open = menu.hidden;
      document.dispatchEvent(new CustomEvent("vr-close-menus"));
      if (open) {
        menu.hidden = false; trigger.setAttribute("aria-expanded", "true");
        var first = menu.querySelector("button, a"); if (first) first.focus();
      }
    });
    menu.addEventListener("keydown", function (e) {
      var items = Array.prototype.slice.call(menu.querySelectorAll("button:not([hidden]), a:not([hidden])"));
      var i = items.indexOf(document.activeElement);
      if (e.key === "Escape") { close(); trigger.focus(); }
      else if (e.key === "ArrowDown") { e.preventDefault(); (items[i + 1] || items[0]).focus(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); (items[i - 1] || items[items.length - 1]).focus(); }
    });
    menu.addEventListener("click", function () { close(); });
    document.addEventListener("vr-close-menus", close);
    return { close: close };
  };
  document.addEventListener("click", function () { document.dispatchEvent(new CustomEvent("vr-close-menus")); });

  // ---------- Register / edit form ----------
  function fieldHtml(o) {
    var id = "vf-" + o.name;
    var req = o.req ? '<span class="req" aria-hidden="true">*</span>' : "";
    var input;
    if (o.type === "textarea") {
      input = '<textarea id="' + id + '" name="' + o.name + '" maxlength="' + (o.max || 5000) + '" rows="' + (o.rows || 3) + '"' +
        (o.ph ? ' placeholder="' + esc(o.ph) + '"' : "") + ' aria-describedby="' + id + '-err"></textarea>';
    } else if (o.type === "combo") {
      input = '<div class="combo"><input id="' + id + '" type="text" data-field="' + o.name + '" placeholder="' + esc(o.ph || "") +
        '" aria-describedby="' + id + '-err"><input type="hidden" name="' + o.name + '"></div>';
    } else if (o.type === "select") {
      input = '<select id="' + id + '" name="' + o.name + '" aria-describedby="' + id + '-err">' + o.options + "</select>";
    } else {
      input = '<input id="' + id + '" name="' + o.name + '" type="' + (o.type || "text") + '"' + (o.max ? ' maxlength="' + o.max + '"' : "") +
        (o.ph ? ' placeholder="' + esc(o.ph) + '"' : "") + (o.extra || "") + ' aria-describedby="' + id + '-err' + (o.hint ? " " + id + "-hint" : "") + '">';
    }
    return '<div class="field' + (o.full ? " full" : "") + '"><label for="' + id + '">' + esc(o.label) + req + "</label>" + input +
      (o.hint ? '<span class="hint" id="' + id + '-hint">' + esc(o.hint) + "</span>" : "") +
      '<span class="err-msg" id="' + id + '-err" data-err="' + o.name + '"></span></div>';
  }
  function section(n, title, inner) {
    return '<section class="card f-card"><div class="f-card-head"><span class="f-step" aria-hidden="true">' + n + "</span><h3>" +
      esc(title) + '</h3></div><div class="f-grid">' + inner + "</div></section>";
  }

  /* Register a new asset in the asset register (same required fields and rules as the asset register form).
     opts: {name (prefill), departmentId, departments, meta (options.assetForm)}. Resolves with the new asset or null. */
  VR.openAssetForm = function (opts) {
    var M = opts.meta;
    return new Promise(function (resolve) {
      var created = null;
      function selectOpts(list, grouped) {
        var out = '<option value="">— Сонгох —</option>', group = null;
        list.forEach(function (o) {
          if (grouped && o.group !== group) {
            if (group !== null) out += "</optgroup>";
            group = o.group; out += '<optgroup label="' + esc(group || "Бусад") + '">';
          }
          out += '<option value="' + esc(o.value) + '">' + esc(o.label) + "</option>";
        });
        return out + (grouped && group !== null ? "</optgroup>" : "");
      }
      var wide = { asset_name: 1, description: 1, asset_group_code: 1 };
      var inner = "";
      if (!M.deptLocked) {
        inner += fieldHtml({ name: "department_id", label: "Хэлтэс", req: true, type: "select", full: true,
          options: selectOpts(opts.departments.map(function (d) { return { value: String(d.id), label: d.name }; })) });
      }
      M.fields.forEach(function (f) {
        var o = { name: f.name, label: f.label, req: f.required, full: !!wide[f.name], max: 300 };
        if (f.options) { o.type = "select"; o.options = selectOpts(f.options, f.name === "asset_group_code"); }
        else if (f.name === "description") { o.type = "textarea"; o.max = 5000; }
        else if (f.name === "retention_period") o.ph = "Жишээ: 5 жил";
        inner += fieldHtml(o);
      });
      inner += fieldHtml({ name: "review_frequency", label: "Хянах давтамж", type: "select",
        options: selectOpts(M.frequencies.map(function (v) { return { value: v, label: v }; })) });
      var dlg = document.createElement("dialog");
      dlg.className = "modal";
      dlg.setAttribute("aria-labelledby", "af-title");
      dlg.innerHTML =
        '<form novalidate><div class="m-head"><div><h2 id="af-title">Шинэ хөрөнгө бүртгэх</h2>' +
        '<p>Хөрөнгийн бүртгэлд нэмэгдэж, энэ эмзэг байдалд холбогдоно. <span class="req">*</span> тэмдэглэгээтэй талбарыг заавал бөглөнө.</p></div>' +
        '<button type="button" class="icon-btn" data-close aria-label="Хаах"><svg class="ico" aria-hidden="true"><use href="#i-x"/></svg></button></div>' +
        '<div class="m-body"><div class="m-alert" role="alert" data-alert></div><div class="f-grid">' + inner + "</div></div>" +
        '<div class="m-foot"><button type="button" class="btn-secondary" data-close>Болих</button>' +
        '<button type="submit" class="btn-primary" data-submit>Хөрөнгө бүртгэх</button></div></form>';
      var form = dlg.querySelector("form");
      var $ = function (n) { return form.querySelector('[name="' + n + '"]'); };
      Array.prototype.forEach.call(form.querySelectorAll("[name]"), function (n) { n.id = "af-" + n.name; });
      Array.prototype.forEach.call(form.querySelectorAll("label[for^='vf-']"), function (l) { l.htmlFor = "af-" + l.htmlFor.slice(3); });
      Array.prototype.forEach.call(form.querySelectorAll("[id^='vf-']"), function (n) { n.id = "af-" + n.id.slice(3); });
      Array.prototype.forEach.call(form.querySelectorAll("[aria-describedby]"), function (n) {
        n.setAttribute("aria-describedby", n.getAttribute("aria-describedby").replace(/vf-/g, "af-"));
      });
      $("asset_name").value = opts.name || "";
      if ($("department_id") && opts.departmentId) $("department_id").value = String(opts.departmentId);
      var alertBox = form.querySelector("[data-alert]"), submitBtn = form.querySelector("[data-submit]");
      form.addEventListener("submit", function (ev) {
        ev.preventDefault();
        ev.stopPropagation();
        var errs = {}, data = {};
        Array.prototype.forEach.call(form.querySelectorAll("[name]"), function (n) { data[n.name] = n.value.trim(); });
        if ($("department_id") && !data.department_id) errs.department_id = "Хэлтэс сонгоно уу.";
        M.fields.forEach(function (f) { if (f.required && !data[f.name]) errs[f.name] = "Заавал бөглөнө."; });
        alertBox.textContent = "";
        if (!VR.setErrors(form, errs)) { alertBox.textContent = "Улаанаар тэмдэглэсэн талбаруудыг бөглөнө үү."; return; }
        submitBtn.disabled = true;
        VR.api(BASE + "/api/assets/create", { form: data }).then(function (r) {
          submitBtn.disabled = false;
          if (!r.ok) {
            alertBox.textContent = r.data.error || "Хөрөнгө бүртгэж чадсангүй.";
            if (r.data.fields) VR.setErrors(form, r.data.fields);
            return;
          }
          created = r.data.asset;
          dlg.close();
        });
      });
      Array.prototype.forEach.call(dlg.querySelectorAll("[data-close]"), function (b) { b.addEventListener("click", function () { dlg.close(); }); });
      dlg.addEventListener("close", function () { dlg.remove(); resolve(created); });
      VR.showModal(dlg, $("asset_name").value ? $("description") : $("asset_name"));
    });
  };

  // ---------- Form designer schema (Settings → Маягтын бүтэц) ----------
  VR.form = function (key) { return ((VR.boot && VR.boot.forms) || {})[key] || { sections: [] }; };
  VR.formFields = function (key) {
    var out = [];
    VR.form(key).sections.forEach(function (s) { s.fields.forEach(function (f) { out.push(f); }); });
    return out;
  };
  VR.formField = function (key, name) { return VR.formFields(key).filter(function (f) { return f.key === name; })[0] || null; };
  /* Label of a built-in field as configured by InfoSec (falls back to the given default). */
  VR.formLabel = function (key, name, dflt) { var f = VR.formField(key, name); return f ? f.label : dflt; };
  VR.formHidden = function (key, name) { var f = VR.formField(key, name); return !!(f && f.hidden); };
  /* Options of a custom select / yes-no field as [[value, label]]. */
  VR.customOptions = function (f) {
    if (f.type === "yesno") return [["yes", "Тийм"], ["no", "Үгүй"]];
    return (f.options || []).map(function (o) { return [o, o]; });
  };
  VR.customText = function (f, v) {
    if (v == null || v === "") return "";
    if (f.type === "yesno") return v === "yes" ? "Тийм" : (v === "no" ? "Үгүй" : v);
    return String(v);
  };
  /* Read-only <dl> rows for the custom fields of a form, grouped by section; "" if there are none. */
  VR.customKv = function (key, values, kv) {
    values = values || {};
    return VR.form(key).sections.map(function (s) {
      var fs = s.fields.filter(function (f) { return !f.builtin && (!f.hidden || values[f.key]); });
      if (!fs.length) return "";
      return '<div class="full"><dt class="cf-sec">' + esc(s.title) + "</dt><dd></dd></div>" + fs.map(function (f) {
        var v = VR.customText(f, values[f.key]);
        var html = !v ? '<span class="muted">Оруулаагүй</span>'
          : (f.type === "url" && /^https?:\/\//i.test(v) ? '<a href="' + esc(v) + '" target="_blank" rel="noopener noreferrer">' + esc(v) + "</a>" : esc(v));
        return kv(f.label, html, { full: f.type === "textarea" || f.full, text: f.type === "textarea" && !!v });
      }).join("");
    }).join("");
  };

  function customFieldOpts(f) {
    var o = { name: f.key, label: f.label, req: f.required, full: !!f.full, hint: f.hint, ph: f.ph };
    if (f.type === "textarea") { o.type = "textarea"; o.max = f.max || 5000; }
    else if (f.type === "number") { o.type = "text"; o.extra = ' inputmode="decimal"'; o.max = 40; }
    else if (f.type === "select" || f.type === "yesno") {
      o.type = "select";
      o.options = '<option value="">— Сонгох —</option>' + VR.customOptions(f).map(function (x) {
        return '<option value="' + esc(x[0]) + '">' + esc(x[1]) + "</option>"; }).join("");
    } else if (f.type === "date") o.type = "date";
    else if (f.type === "url") { o.type = "url"; o.max = 2000; }
    else if (f.type === "email") { o.type = "email"; o.max = 254; }
    else o.max = f.max || 300;
    return o;
  }
  // Fixed rendering details of the built-in registration fields; label / hint / placeholder / width come from the schema.
  var REG_EXTRA = {
    title: { max: 300 }, cve_id: { max: 32 }, source: { max: 200, extra: ' list="vf-sources"' },
    source_url: { type: "url", max: 2000 }, published_date: { type: "date" }, reported_date: { type: "date" },
    description: { type: "textarea", max: 10000, rows: 4 }, due_date: { type: "date" },
    impact: { type: "textarea" }, risk_justification: { type: "textarea" }, threat_trend: { type: "textarea" },
    scope: { type: "textarea" }, verification_method: { type: "textarea" },
    recommendation: { type: "textarea", max: 10000, rows: 4 }
  };
  function cvssBlock(f) {
    return '<div class="field full"><label for="vf-cvss_score">' + esc(f.label) + '<span class="req">*</span></label><div class="cvss-row">' +
      '<input id="vf-cvss_score" name="cvss_score" type="number" min="0" max="10" step="0.1" inputmode="decimal" placeholder="0.0 – 10.0" aria-describedby="vf-cvss_score-err">' +
      '<div class="cvss-meter" aria-hidden="true"><span data-meter></span></div></div>' +
      (f.hint ? '<span class="hint">' + esc(f.hint) + "</span>" : "") +
      '<span class="err-msg" id="vf-cvss_score-err" data-err="cvss_score"></span></div>' +
      '<div class="field"><span class="label">Түвшин (Severity)</span><output class="derived" data-sev aria-live="polite">' + VR.sevPill("") + '</output><span class="hint">CVSS онооноос автоматаар тодорхойлогдоно.</span></div>' +
      '<div class="field"><span class="label">SLA</span><output class="derived" data-sla>—</output><span class="hint">Critical 5 · High 30 · Medium 60 · Low 90 хоног</span></div>';
  }
  function registerSections() {
    return VR.form("register").sections.map(function (s, i) {
      var inner = s.fields.filter(function (f) { return !f.hidden; }).map(function (f) {
        if (f.key === "cvss_score") return cvssBlock(f);
        if (!f.builtin) return fieldHtml(customFieldOpts(f));
        var o = { name: f.key, label: f.label, req: f.required, full: !!f.full, hint: f.hint, ph: f.ph };
        var x = REG_EXTRA[f.key] || {};
        Object.keys(x).forEach(function (k) { o[k] = x[k]; });
        return fieldHtml(o);
      }).join("");
      if (s.desc) inner = '<div class="m-alert info full">' + esc(s.desc) + "</div>" + inner;
      return section(i + 1, s.title, inner);
    }).join("");
  }

  /* «Хариуцагч сонгох» window shown when a new registration is submitted: picks the person who reviews the record
     and assigns the engineer (acts as the IT Head for it).
     Resolves to the chosen user id, or "" if cancelled. */
  VR.pickResponsible = function (people, title) {
    return new Promise(function (resolve) {
      var dlg = document.createElement("dialog");
      dlg.className = "modal narrow";
      dlg.setAttribute("aria-labelledby", "rp-title");
      dlg.innerHTML =
        '<form novalidate><div class="m-head"><div><h2 id="rp-title">Хариуцагч сонгох</h2>' +
        (title ? "<p>" + esc(title) + "</p>" : "") + "</div>" +
        '<button type="button" class="icon-btn" data-close aria-label="Хаах"><svg class="ico" aria-hidden="true"><use href="#i-x"/></svg></button></div>' +
        '<div class="m-body">' +
        (people.length ? "" : '<div class="m-alert">Идэвхтэй хэрэглэгч олдсонгүй.</div>') +
        '<div class="field"><label for="rp-user">Хариуцагч (инженер томилох)<span class="req">*</span></label>' +
        '<div class="combo"><input id="rp-user" type="text" placeholder="Ажилтны нэрээр хайх…"><input type="hidden" name="rp_assignee"></div>' +
        '<span class="err-msg" data-err="rp_assignee"></span></div>' +
        '<p class="hint" style="margin:0">Бүртгэл IT-ийн даргын оронд сонгосон хүнд очно. Тэр хянаж, мэдээлэл дутуу бол буцааж, ' +
        "засварлах инженерийг томилно. Сонгосон хүнд и-мэйлээр мэдэгдэл очно.</p></div>" +
        '<div class="m-foot"><button type="button" class="btn-secondary" data-close>Буцах</button>' +
        '<button type="submit" class="btn-primary">Бүртгэх</button></div></form>';
      var form = dlg.querySelector("form"), hidden = form.querySelector('[name="rp_assignee"]');
      VR.combo(form.querySelector("#rp-user"), hidden,
        people.map(function (u) { return { id: u.id, label: u.name, sub: u.dept }; }));
      var result = "";
      form.addEventListener("submit", function (ev) {
        ev.preventDefault();
        if (!hidden.value) { VR.setErrors(form, { rp_assignee: "Жагсаалтаас сонгоно уу." }); return; }
        result = hidden.value;
        dlg.close();
      });
      Array.prototype.forEach.call(dlg.querySelectorAll("[data-close]"), function (b) { b.addEventListener("click", function () { dlg.close(); }); });
      dlg.addEventListener("close", function () { dlg.remove(); resolve(result); });
      VR.showModal(dlg, form.querySelector("#rp-user"));
    });
  };

  /* opts: {record (detail item, for edit), onSaved(data)} */
  VR.openVulnForm = function (opts) {
    opts = opts || {};
    var rec = opts.record || null;
    var editing = !!rec;
    return VR.options().then(function (O) {
      var dlg = document.createElement("dialog");
      dlg.className = "modal";
      dlg.setAttribute("aria-labelledby", "vf-heading");
      dlg.innerHTML =
        '<form novalidate><div class="m-head"><div><h2 id="vf-heading">' + (editing ? "Эмзэг байдал засах" : "Эмзэг байдал бүртгэх") + "</h2>" +
        "<p>" + (editing ? esc(rec.ref) + " · " : "") + '<span class="req">*</span> тэмдэглэгээтэй талбарыг заавал бөглөнө.</p></div>' +
        '<button type="button" class="icon-btn" data-close aria-label="Хаах"><svg class="ico" aria-hidden="true"><use href="#i-x"/></svg></button></div>' +
        '<div class="m-body"><div class="m-alert" role="alert" data-alert></div>' +
        registerSections() +
        '<datalist id="vf-sources"><option value="NVD"><option value="CISA KEV"><option value="Вендорын зөвлөмж"><option value="Дотоод скан"><option value="Нэвтрэлтийн тест"><option value="MN-CERT"></datalist>' +
        '</div><div class="m-foot"><button type="button" class="btn-secondary" data-close>Болих</button>' +
        '<button type="submit" class="btn-primary" data-submit>' + (editing ? "Хадгалах" : "Бүртгэх") + "</button></div></form>";
      var form = dlg.querySelector("form");
      var $ = function (n) { return form.querySelector('[name="' + n + '"]'); };
      // Fields can be hidden in the form designer: read/write through these null-safe helpers.
      var val = function (n) { var el = $(n); return el ? el.value.trim() : ""; };
      var on = function (n, ev, fn) { var el = $(n); if (el) el.addEventListener(ev, fn); };
      if ($("published_date")) $("published_date").max = VR.todayIso;
      if ($("reported_date")) $("reported_date").max = VR.todayIso;

      // Deadline auto-fills from CVSS until edited by hand; clearing it resumes auto-fill.
      function autoDue(score, reported) {
        if (score == null || score === "") return "";
        var d = VR.cvssRating(Math.round(parseFloat(score) * 10) / 10).days;
        return d === null ? "" : VR.addDays(reported || VR.todayIso, d);
      }
      // When editing, keep a stored date only if it differs from what CVSS would have produced (i.e. was set by hand).
      var dueTouched = editing && !!rec.due && rec.due !== autoDue(rec.cvss, rec.reported);
      on("due_date", "input", function () { dueTouched = this.value !== ""; if (!dueTouched) updateCvss(); });
      function setDue(v) { if ($("due_date")) $("due_date").value = v; }
      function updateCvss() {
        var raw = $("cvss_score").value.trim(), bar = form.querySelector("[data-meter]");
        var v = Math.round(parseFloat(raw) * 10) / 10;
        var sevOut = form.querySelector("[data-sev]"), sla = form.querySelector("[data-sla]");
        if (raw === "" || isNaN(v) || v < 0 || v > 10) {
          sevOut.innerHTML = VR.sevPill("") + (raw === "" ? "" : ' <span class="muted">Буруу утга</span>');
          sla.textContent = "—"; bar.style.width = "0";
          if (!dueTouched) setDue("");
          return;
        }
        var r = VR.cvssRating(v);
        sevOut.innerHTML = VR.sevPill(r.key) + ' <span class="muted">CVSS ' + v.toFixed(1) + "</span>";
        sla.textContent = r.days === null ? "Хугацаагүй" : r.days + " хоног";
        bar.style.width = (v * 10) + "%"; bar.style.background = r.color;
        if (!dueTouched) setDue(r.days === null ? "" : VR.addDays(val("reported_date") || (editing && rec.reported) || VR.todayIso, r.days));
      }
      $("cvss_score").addEventListener("input", updateCvss);
      on("reported_date", "change", updateCvss);
      on("published_date", "change", function () { if ($("reported_date")) $("reported_date").min = this.value || ""; });

      var custom = (editing && rec.custom) || {};
      VR.formFields("register").forEach(function (f) { if (!f.builtin && $(f.key)) $(f.key).value = custom[f.key] || ""; });
      if (editing) {
        var map = { title: rec.title, cve_id: rec.cve, source: rec.source, source_url: rec.sourceUrl, published_date: rec.published,
          reported_date: rec.reported, description: rec.description, due_date: rec.due, cvss_score: rec.cvss != null ? Number(rec.cvss).toFixed(1) : "",
          impact: rec.impact, risk_justification: rec.riskJustification, threat_trend: rec.threatTrend, scope: rec.scope,
          verification_method: rec.verification, recommendation: rec.recommendation };
        Object.keys(map).forEach(function (k) { if ($(k)) $(k).value = map[k] || ""; });
      } else if ($("reported_date")) {
        $("reported_date").value = VR.todayIso;
      }
      updateCvss();

      function validate() {
        var e = {};
        VR.formFields("register").forEach(function (f) {
          if (f.hidden || !f.required || f.block || !$(f.key)) return;
          if (!val(f.key)) e[f.key] = "Заавал бөглөнө.";
        });
        var cve = val("cve_id").toUpperCase(); if ($("cve_id")) $("cve_id").value = cve;
        if (!val("title")) e.title = "Нэр заавал бөглөнө.";
        if (cve && !/^CVE-\d{4}-\d{4,}$/.test(cve)) e.cve_id = "Формат: CVE-YYYY-NNNN";
        var url = val("source_url");
        if (url && !/^https?:\/\/[^\s\/]+/i.test(url)) e.source_url = "http:// эсвэл https://-ээр эхэлсэн холбоос оруулна уу.";
        var pub = val("published_date"), rep = val("reported_date");
        if (pub && pub > VR.todayIso) e.published_date = "Ирээдүйн огноо байж болохгүй.";
        if (rep && rep > VR.todayIso) e.reported_date = "Ирээдүйн огноо байж болохгүй.";
        else if (pub && rep && rep < pub) e.reported_date = "Нийтэлсэн огнооноос өмнө байж болохгүй.";
        var due = val("due_date");
        if (due && rep && due < rep) e.due_date = "Мэдээлсэн огнооноос өмнө байж болохгүй.";
        var c = $("cvss_score").value.trim(), cv = parseFloat(c);
        if (c && (isNaN(cv) || cv < 0 || cv > 10)) e.cvss_score = "0.0 – 10.0 хооронд утга оруулна уу.";
        if (!c && !editing) e.cvss_score = "CVSS оноо заавал оруулна.";
        return e;
      }
      var alertBox = form.querySelector("[data-alert]");
      var submitBtn = form.querySelector("[data-submit]");
      form.addEventListener("submit", function (ev) {
        ev.preventDefault();
        var errs = validate();
        alertBox.textContent = "";
        if (!VR.setErrors(form, errs)) { alertBox.textContent = "Улаанаар тэмдэглэсэн талбаруудыг засна уу."; return; }
        var data = {};
        Array.prototype.forEach.call(form.querySelectorAll("[name]"), function (n) { if (!n.disabled) data[n.name] = n.value; });
        function send() {
          submitBtn.disabled = true;
          VR.api(editing ? BASE + "/api/" + rec.id + "/update" : BASE + "/api/create", { form: data }).then(function (r) {
            submitBtn.disabled = false;
            if (!r.ok) {
              alertBox.textContent = r.data.error || "Хадгалж чадсангүй.";
              if (r.data.fields) VR.setErrors(form, r.data.fields);
              return;
            }
            dlg.close();
            if (opts.onSaved) opts.onSaved(r.data);
          });
        }
        if (editing) { send(); return; }
        // New registration: the registrant chooses the responsible person, who acts as the IT Head for this record
        // (reviews it and assigns the engineer) — instead of the record going to the IT Head automatically.
        VR.pickResponsible(O.people || [], data.title || "").then(function (id) {
          if (!id) return;
          data.reviewer_id = id;
          send();
        });
      });
      Array.prototype.forEach.call(dlg.querySelectorAll("[data-close]"), function (b) { b.addEventListener("click", function () { dlg.close(); }); });
      dlg.addEventListener("close", function () { dlg.remove(); });
      VR.showModal(dlg, $("title"));
    }, function (err) {
      VR.toast(err.message || "Лавлах мэдээлэл ачаалж чадсангүй.", "err");
    });
  };
})();
