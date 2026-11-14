/* ============================================================
   Attack evolution  -  loaded after main.js, does not edit it.
   The defense run is exactly as before; when "Also evolve the attack"
   is ticked, a second job (/api/evolve) runs the attack CCEA and its
   results are shown below each sample's defense results.
   ============================================================ */
(function () {
  const box = $("#evolve");
  const llmBox = $("#use-llm");
  if (!box) return;
  const sync = () => { box.disabled = !!llmBox?.checked; if (llmBox?.checked) box.checked = false; };
  llmBox?.addEventListener("change", sync);
  sync();

  let evoJob = null, evo = null, evoStatus = "", evoProg = null, evoCharts = [], showAll = false;

  const baseAnalyze = analyze;
  const baseRenderPanel = renderPanel;

  analyze = function (file) {
    evo = null; evoJob = null; evoStatus = ""; evoProg = null;
    const run = baseAnalyze(file);
    // start only after the defense run has finished: the defense core uses one shared
    // random generator, so two runs at the same time would change each other's results
    if (box.checked) {
      evoStatus = "Waiting for the defense run to finish…";
      Promise.resolve(run).finally(() => { if (lastResult) startEvolve(file); });
    }
    return run;
  };

  renderPanel = function () {
    baseRenderPanel();
    renderEvo();
  };

  async function startEvolve(file) {
    const fd = new FormData();
    fd.append("file", file);
    evoStatus = "Starting the attack evolution…";
    try {
      const res = await fetch(`${API_BASE}/api/evolve`, { method: "POST", body: fd });
      const d = await res.json();
      if (!res.ok) { evoStatus = d?.error || `Attack evolution failed (${res.status}).`; renderEvo(); return; }
      evoJob = d.job_id;
      poll(d.job_id);
    } catch (e) {
      evoStatus = `Could not start the attack evolution (${e.message}).`;
      renderEvo();
    }
  }

  async function poll(id) {
    if (id !== evoJob) return;
    let j;
    try {
      j = await (await fetch(`${API_BASE}/api/jobs/${id}`)).json();
    } catch (e) {
      evoStatus = `Lost contact with the backend (${e.message}).`;
      renderEvo();
      return;
    }
    if (id !== evoJob) return;
    if (j.status === "running") {
      evoProg = j.total ? j.done / j.total : null;
      evoStatus = `Evolving the attack: ${j.done} of ${j.total} samples done` + (j.current_pair ? ` · ${j.current_pair}` : "");
      renderEvo();
      setTimeout(() => poll(id), 1500);
      return;
    }
    if (j.status === "failed") { evoStatus = j.error || "Attack evolution failed."; evoProg = null; renderEvo(); return; }
    evo = {};
    j.result.samples.forEach(s => { evo[s.hash] = s; });
    evoStatus = ""; evoProg = null;
    renderEvo();
  }

  const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;" };
  const esc = t => String(t ?? "").replace(/[&<>"]/g, c => ESC[c]);
  const plural = (n, w, many) => `${n} ${n === 1 ? w : (many || w + "s")}`;

  function card(k, v, sub) {
    return `<div class="evo-card"><div class="k">${k}</div><div class="v">${v}</div>${sub ? `<div class="s">${sub}</div>` : ""}</div>`;
  }

  function repoBlock(f) {
    const head = f.found
      ? `Found in the public repository: ${plural(f.n_samples, "real ransomware sample")} from ${plural(f.n_families, "family", "families")}`
      : "Not found in the public repository";
    const why = f.found
      ? "Each of these real samples has its whole signature list inside the evolved sample, and needs at least one signature the evolution swapped in."
      : "No real sample has its whole signature list inside the evolved sample together with a swapped-in signature.";
    return `<div class="evo-repo ${f.found ? "ok" : "na"}">
      <div class="evo-repo-head"><b>${head}</b>
        <a href="${esc(f.repo_url)}" target="_blank" rel="noopener">MLRan on Zenodo ↗</a></div>
      <p>${why} The repository (${Number(f.repo_size).toLocaleString()} real samples, CC-BY 4.0) is held out: the attack never uses it to choose anything.</p>
      ${f.found ? `<div class="chips">${f.families.map(x => `<span class="chip">${esc(x)}</span>`).join("")}</div>
        <p class="evo-note">Real samples found (identical lists grouped; bold = signature added by the evolution):</p>
        <ul class="evo-examples">${f.examples.map(x => `<li><span class="fam">${esc(x.families.join(", "))}</span>${
          x.signatures.map(n => x.new_signatures.includes(n) ? `<b>${esc(n)}</b>` : esc(n)).join(", ")}</li>`).join("")}</ul>` : ""}
    </div>`;
  }

  function renderEvo() {
    const panel = $("[data-panel]");
    if (!panel || !lastResult || !(evoJob || evoStatus || evo)) return;
    let sec = $("[data-evo]", panel);
    if (!sec) {
      sec = document.createElement("section");
      sec.setAttribute("data-evo", "");
      sec.className = "evo";
      panel.appendChild(sec);
    }
    evoCharts.forEach(c => c.destroy());
    evoCharts = [];

    const s = evo && evo[activeHash];
    if (!s) {
      sec.innerHTML = `<h3 class="evo-title">Attack evolution</h3>
        <p class="evo-status">${esc(evoStatus || "Waiting for results…")}</p>
        ${evoProg != null ? `<div class="evo-bar"><span style="width:${Math.max(4, evoProg * 100).toFixed(0)}%"></span></div>` : ""}`;
      return;
    }

    const rel = s.swaps.filter(w => w.link === "related").length;
    const rnd = s.swaps.length - rel;
    const stop = s.stopped_by === "patience" ? "stopped after 20 generations without a harder sample" : "stopped at the 100-generation limit";
    const changedRows = s.defense_before_after.filter(r => r.status !== "same");
    const rows = showAll ? s.defense_before_after : changedRows;

    sec.innerHTML = `
      <h3 class="evo-title">Attack evolution</h3>
      <p class="evo-sub">Each signature of the sample can change to a related signature (shared MITRE tag), or to one of 4 random ones if it has none.
        The attack evolves like the defense (a CCEA) and keeps the version that is hardest to defend; the defense answers every version.</p>

      <div class="evo-cards">
        ${card("Defense score F", `${fmt(s.F_original, 4)} → ${fmt(s.F_evolved, 4)}`, "original → evolved sample")}
        ${card("Attack score 1 − F", `${fmt(1 - s.F_original, 3)} → ${fmt(1 - s.F_evolved, 3)}`, "higher = harder to defend")}
        ${card("Signatures changed", `${s.swaps.length} <small>of ${s.slots.total}</small>`, `${rel} related · ${rnd} random`)}
        ${card("Generations", s.generations_run, `best found in generation ${s.best_generation}`)}
      </div>

      ${repoBlock(s.found_in_repo)}

      <div class="evo-charts">
        <div class="evo-chart"><h4>Attack evolution</h4><div class="chart-box"><canvas id="evo-att"></canvas></div></div>
        <div class="evo-chart"><h4>Defense on the original and the evolved sample</h4><div class="chart-box"><canvas id="evo-def"></canvas></div></div>
      </div>

      <h4 class="evo-h">Signatures that changed</h4>
      ${s.swaps.length ? `<div class="tbl-scroll"><table class="combo">
        <thead><tr><th>Original signature</th><th></th><th>Evolved signature</th><th>Link</th></tr></thead>
        <tbody>${s.swaps.map(w => `<tr class="in"><td>${esc(w.old_name)}</td><td class="arrow">→</td><td>${esc(w.new_name)}</td>
          <td><span class="st st-${w.link}">${w.link === "related" ? "related (shared tag)" : "random"}</span></td></tr>`).join("")}</tbody>
      </table></div>` : `<p class="evo-status">No signature changed: no evolved version was harder to defend than the original sample.</p>`}

      <div class="evo-h evo-h-row"><h4>Best defense, before and after</h4>
        <div class="evo-filter" role="group">
          <button data-f="changed" class="${showAll ? "" : "is-on"}">Changed and new (${changedRows.length})</button>
          <button data-f="all" class="${showAll ? "is-on" : ""}">All (${s.defense_before_after.length})</button>
        </div></div>
      ${rows.length ? `<div class="tbl-scroll"><table class="combo">
        <thead><tr><th>Signature</th><th>Defense (original sample)</th><th>Defense (evolved sample)</th><th>Status</th></tr></thead>
        <tbody>${rows.map(r => `<tr class="in"><td>${esc(r.signature)}</td><td>${esc(r.defense_before || "—")}</td>
          <td>${esc(r.defense_after)}</td><td><span class="st st-${r.status.replace(" ", "-")}">${esc(r.status)}</span></td></tr>`).join("")}</tbody>
      </table></div>` : `<p class="evo-status">Every signature keeps the same defense.</p>`}

      <div class="evo-foot">
        <span>Seed ${s.seed} · ${stop}</span>
        <button class="download evo-dl"><i class="fa-solid fa-download"></i> Attack evolution results (CSV)</button>
      </div>`;

    $(".evo-dl", sec).addEventListener("click", download);
    $$(".evo-filter button", sec).forEach(b => b.addEventListener("click", () => { showAll = b.dataset.f === "all"; renderEvo(); }));

    evoCharts.push(chart("evo-att", "Generation", "Attack score 1 − F", [
      { label: "Each generation", pts: s.history.map(h => [h.generation, h.generation_attack]), color: "rgba(224,164,88,.45)", dots: true },
      { label: "Hardest so far", pts: s.history.map(h => [h.generation, h.attack_strength]), color: "#e0a458" },
    ]));
    evoCharts.push(chart("evo-def", "Defense generation", "Best defense score F", [
      { label: "Original sample", pts: s.defense_curve_original.map(g => [g.generation, g.best_F]), color: "#ffffff" },
      { label: "Evolved sample", pts: s.defense_curve_evolved.map(g => [g.generation, g.best_F]), color: "#e0a458" },
    ]));
  }

  function chart(id, xt, yt, series) {
    const axis = t => ({
      type: "linear", title: { display: true, text: t, color: "#8e8e8e" },
      ticks: { color: "#8e8e8e", maxTicksLimit: 8 }, grid: { color: "rgba(255,255,255,.06)" },
    });
    return new Chart($("#" + id).getContext("2d"), {
      type: "line",
      data: {
        datasets: series.map(s => ({
          label: s.label, data: s.pts.map(([x, y]) => ({ x, y })),
          borderColor: s.color, backgroundColor: s.color,
          borderWidth: 2, pointRadius: s.dots ? 2.5 : 0, showLine: !s.dots, stepped: !s.dots,
        })),
      },
      options: {
        responsive: true, maintainAspectRatio: false, animation: false,
        interaction: { mode: "nearest", intersect: false },
        plugins: {
          legend: { labels: { color: "#b9b9b9", boxWidth: 12, font: { size: 11 } } },
          tooltip: { callbacks: { label: c => `${c.dataset.label}: ${Number(c.parsed.y).toFixed(4)}` } },
        },
        scales: { x: axis(xt), y: axis(yt) },
      },
    });
  }

  async function download() {
    const res = await fetch(`${API_BASE}/api/evolve/${evoJob}/download`);
    if (!res.ok) { alert("Download failed."); return; }
    const url = URL.createObjectURL(await res.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = "attack_evolution_results.csv";
    a.click();
    URL.revokeObjectURL(url);
  }

  $("[data-back]")?.addEventListener("click", () => { evoJob = null; evo = null; evoStatus = ""; evoProg = null; });
})();
