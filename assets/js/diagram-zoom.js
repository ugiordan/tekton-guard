// Diagram controls for Mermaid and D2 diagrams in mkdocs-material.
//
// Wraps diagrams in a .diagram-wrapper with +/- zoom, reset, and fullscreen.
// Mermaid: uses CSS "zoom" (shadow DOM prevents other approaches).
// D2: uses transform:scale on the SVG (inline SVG with fixed dimensions).
(function () {
  var ZOOM_STEP = 0.25;
  var MIN_ZOOM = 0.5;
  var MAX_ZOOM = 5;

  function isD2(div) {
    return div.classList.contains("d2");
  }

  function applyZoom(div, level, wrapper) {
    if (isD2(div)) {
      var svg = div.querySelector("svg");
      if (svg) {
        svg.style.transform = level === 1 ? "" : "scale(" + level + ")";
        svg.style.transformOrigin = "top left";
      }
    } else {
      div.style.zoom = level === 1 ? "" : level;
    }

    if (wrapper) {
      if (level === 1) {
        wrapper.style.overflow = "";
        wrapper.classList.toggle(
          "clipped",
          div.scrollHeight > wrapper.clientHeight + 10
        );
      } else {
        wrapper.style.overflow = "auto";
        wrapper.classList.remove("clipped");
      }
    }
  }

  function addControls(div) {
    if (div._hasControls) return;
    if (div.tagName !== "DIV") return;
    if (div.closest(".diagram-wrapper")) return;
    div._hasControls = true;
    div._zoomLevel = 1;

    var wrapper = document.createElement("div");
    wrapper.className = "diagram-wrapper";
    div.parentNode.insertBefore(wrapper, div);
    wrapper.appendChild(div);

    requestAnimationFrame(function () {
      setTimeout(function () {
        if (div.scrollHeight > wrapper.clientHeight + 10) {
          wrapper.classList.add("clipped");
        }
      }, 2000);
    });

    var bar = document.createElement("div");
    bar.className = "diagram-actions";
    bar.innerHTML =
      '<button data-action="zoom-in" title="Zoom in">&#43;</button>' +
      '<button data-action="zoom-out" title="Zoom out">&#8722;</button>' +
      '<button data-action="reset" title="Reset zoom">1:1</button>' +
      '<button data-action="fullscreen" title="View full screen">&#9974;</button>';
    wrapper.after(bar);
  }

  function scanAll() {
    document.querySelectorAll("div.mermaid, div.d2").forEach(addControls);
  }

  function openFullscreen(diagramDiv) {
    var overlay = document.createElement("div");
    overlay.className = "diagram-overlay";

    var toolbar = document.createElement("div");
    toolbar.className = "diagram-overlay-toolbar";
    toolbar.innerHTML =
      '<button data-action="ol-zoom-in" title="Zoom in">&#43;</button>' +
      '<button data-action="ol-zoom-out" title="Zoom out">&#8722;</button>' +
      '<button data-action="ol-reset" title="Reset">1:1</button>' +
      '<button data-action="ol-close" title="Close">&#10005;</button>';
    overlay.appendChild(toolbar);

    var container = document.createElement("div");
    container.className = "diagram-overlay-content";

    var wrapper = diagramDiv.parentNode;
    var placeholder = document.createElement("div");
    placeholder.style.display = "none";
    wrapper.insertBefore(placeholder, diagramDiv);

    var origStyle = diagramDiv.style.cssText;
    var origSvgStyles = [];

    if (isD2(diagramDiv)) {
      diagramDiv.style.cssText = "overflow:visible;";
      diagramDiv.querySelectorAll("svg").forEach(function (svg, i) {
        origSvgStyles[i] = svg.style.cssText;
        svg.style.transform = "";
      });
    } else {
      diagramDiv.style.cssText =
        "max-width:none; max-height:none; overflow:visible; zoom:1;";
    }

    container.appendChild(diagramDiv);
    overlay.appendChild(container);
    document.body.appendChild(overlay);

    var olZoom = 1;

    if (isD2(diagramDiv)) {
      // D2 SVGs have no width/height attrs, need explicit container width
      var availW = container.clientWidth - 64;
      diagramDiv.style.width = availW + "px";
    } else {
      var naturalW = diagramDiv.scrollWidth || diagramDiv.offsetWidth;
      var naturalH = diagramDiv.scrollHeight || diagramDiv.offsetHeight;
      var availW = container.clientWidth - 64;
      var availH = container.clientHeight - 32;
      var fitZoom = 1;
      if (naturalW > 0 && naturalH > 0) {
        fitZoom = Math.min(availW / naturalW, availH / naturalH, 3);
        fitZoom = Math.max(fitZoom, 0.5);
      }
      diagramDiv.style.zoom = fitZoom;
      olZoom = fitZoom;
    }

    function close() {
      diagramDiv.style.cssText = origStyle;
      if (isD2(diagramDiv)) {
        diagramDiv.querySelectorAll("svg").forEach(function (svg, i) {
          svg.style.cssText = origSvgStyles[i] || "";
        });
      }
      wrapper.insertBefore(diagramDiv, placeholder);
      placeholder.remove();
      overlay.remove();
      document.removeEventListener("keydown", escHandler);
    }

    function escHandler(e) {
      if (e.key === "Escape") close();
    }
    document.addEventListener("keydown", escHandler);
    overlay.addEventListener("click", function (e) {
      if (e.target === overlay || e.target === container) close();
    });

    toolbar.addEventListener("click", function (e) {
      var btn = e.target.closest("button");
      if (!btn) return;
      var action = btn.dataset.action;
      if (action === "ol-close") {
        close();
        return;
      }
      if (action === "ol-zoom-in")
        olZoom = Math.min(olZoom + ZOOM_STEP, MAX_ZOOM);
      if (action === "ol-zoom-out")
        olZoom = Math.max(olZoom - ZOOM_STEP, MIN_ZOOM);
      if (action === "ol-reset") olZoom = 1;

      if (isD2(diagramDiv)) {
        var baseW = container.clientWidth - 64;
        diagramDiv.style.width = Math.round(baseW * olZoom) + "px";
      } else {
        diagramDiv.style.zoom = olZoom === 1 ? "" : olZoom;
      }
    });
  }

  // Click delegation (capture phase)
  document.addEventListener(
    "click",
    function (e) {
      var btn = e.target.closest(".diagram-actions button");
      if (!btn) return;
      e.preventDefault();
      e.stopPropagation();
      e.stopImmediatePropagation();

      var bar = btn.closest(".diagram-actions");
      var wrapper = bar.previousElementSibling;
      if (!wrapper || !wrapper.classList.contains("diagram-wrapper")) return;
      var diagramDiv =
        wrapper.querySelector("div.mermaid") ||
        wrapper.querySelector("div.d2");
      if (!diagramDiv) return;

      var action = btn.dataset.action;

      if (action === "fullscreen") {
        openFullscreen(diagramDiv);
        return;
      }

      if (!diagramDiv._zoomLevel) diagramDiv._zoomLevel = 1;
      if (action === "zoom-in")
        diagramDiv._zoomLevel = Math.min(
          diagramDiv._zoomLevel + ZOOM_STEP,
          MAX_ZOOM
        );
      if (action === "zoom-out")
        diagramDiv._zoomLevel = Math.max(
          diagramDiv._zoomLevel - ZOOM_STEP,
          MIN_ZOOM
        );
      if (action === "reset") diagramDiv._zoomLevel = 1;

      applyZoom(diagramDiv, diagramDiv._zoomLevel, wrapper);
    },
    true
  );

  // Poll for rendered diagrams
  var pollCount = 0;
  var pollId = setInterval(function () {
    scanAll();
    if (++pollCount > 30) clearInterval(pollId);
  }, 1000);

  var raf = false;
  new MutationObserver(function () {
    if (raf) return;
    raf = true;
    requestAnimationFrame(function () {
      raf = false;
      scanAll();
    });
  }).observe(document.body, { childList: true, subtree: true });

  if (typeof document$ !== "undefined") {
    document$.subscribe(function () {
      pollCount = 0;
      pollId = setInterval(function () {
        scanAll();
        if (++pollCount > 30) clearInterval(pollId);
      }, 1000);
    });
  }
})();
