// JWT verifier page: cache status polling + local JWKS demo controls.
// All calls are same-origin (the verifier proxies the mock JWKS service).

async function refreshCacheState() {
  const box = document.getElementById("cache-state");
  if (!box) return;
  try {
    const resp = await fetch("/api/jwks/cache");
    const d = await resp.json();
    const state = d.fresh
      ? `<em class="tag" style="background:#dcfce7;color:#15803d">有效</em>`
      : d.has_cache
        ? `<em class="tag" style="background:#fef3c7;color:#92400e">已过期</em>`
        : `<em class="tag" style="background:#fee2e2;color:#b91c1c">无缓存</em>`;
    box.innerHTML = `
      <div>${state}
        缓存 kid：${d.cached_kids.length ? d.cached_kids.map(k => "<code>" + k + "</code>").join(", ") : "（无）"}
      </div>
      <div style="margin-top:6px">
        缓存年龄：${d.age_seconds === null ? "—" : d.age_seconds + "s"} ·
        剩余有效期：${d.expires_in === null ? "—" : d.expires_in + "s"}（TTL ${d.ttl_seconds}s）<br>
        实际发起请求：${d.fetch_count} 次 · 节流拦截：${d.suppressed_refreshes} 次
        ${d.last_refresh_error ? `<br><span style="color:#b91c1c">上次刷新失败：${d.last_refresh_error}</span>` : ""}
      </div>`;
  } catch (err) {
    box.textContent = "缓存状态获取失败：" + err;
  }
}

function flash(message, ok = true) {
  const el = document.getElementById("demo-msg");
  if (!el) return;
  el.textContent = message;
  el.style.color = ok ? "#15803d" : "#b91c1c";
}

async function demoAction(action) {
  try {
    const resp = await fetch("/demo/" + action, { method: "POST" });
    const data = await resp.json();
    if (!resp.ok) {
      flash("操作失败：" + (data.error || resp.status), false);
    } else {
      flash("已执行：" + action);
    }
  } catch (err) {
    flash("演示源不可达：" + err, false);
  }
  refreshCacheState();
}

async function loadToken(scenario, label) {
  try {
    const resp = await fetch("/demo/tokens/" + encodeURIComponent(scenario));
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.error || resp.status);
    const area = document.querySelector("textarea[name=token]");
    area.value = data.token;
    flash("已填入示例：" + label);
    area.scrollIntoView({ behavior: "smooth", block: "center" });
  } catch (err) {
    flash("示例令牌获取失败：" + err, false);
  }
}

async function initTokenButtons() {
  const box = document.getElementById("token-buttons");
  if (!box) return;
  try {
    const resp = await fetch("/demo/tokens");
    const data = await resp.json();
    box.innerHTML = "";
    data.scenarios.forEach(([scenario, label]) => {
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "btn secondary";
      btn.textContent = label;
      btn.addEventListener("click", () => loadToken(scenario, label));
      box.appendChild(btn);
    });
  } catch (err) {
    box.innerHTML = '<span class="hint">示例列表加载失败：' + err + "</span>";
  }
}

document.addEventListener("DOMContentLoaded", () => {
  refreshCacheState();
  setInterval(refreshCacheState, 2000);
  document.querySelectorAll(".demo-btn").forEach((btn) => {
    btn.addEventListener("click", () => demoAction(btn.dataset.action));
  });
  initTokenButtons();
});
