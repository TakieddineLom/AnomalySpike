const pageMeta = {
    dashboard: { label: "Command center", title: "Security overview" },
    alerts: { label: "Detection feed", title: "Suricata alerts" },
    connections: { label: "Network telemetry", title: "Connections" },
    dns: { label: "Resolution intelligence", title: "DNS analysis" },
    threats: { label: "Behavioral models", title: "Threat detection" },
    hosts: { label: "Asset inventory", title: "Connected hosts" },
    settings: { label: "System control", title: "Settings" }
};

function decorateTopbar(activePage) {
    const topbar = document.querySelector(".topbar");
    if (!topbar || topbar.dataset.enhanced === "true") return;
    topbar.dataset.enhanced = "true";

    const existingLogo = topbar.querySelector(".logo");
    if (existingLogo) {
        existingLogo.innerHTML = `<span class="topbar-mark" aria-hidden="true"><img src="/static/assets/anomalyspike-logo.png" alt="" /></span><span class="topbar-wordmark">AnomalySpike<span>.</span></span>`;
        existingLogo.setAttribute("aria-label", "AnomalySpike");
    }

    const menuButton = document.createElement("button");
    menuButton.className = "menu-toggle";
    menuButton.type = "button";
    menuButton.setAttribute("aria-label", "Open navigation");
    menuButton.setAttribute("aria-expanded", "false");
    menuButton.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16" /></svg>`;
    topbar.prepend(menuButton);

    const subtitle = topbar.querySelector(".subtitle");
    if (subtitle && pageMeta[activePage]) subtitle.textContent = pageMeta[activePage].title;

    const overlay = document.createElement("button");
    overlay.className = "sidebar-overlay";
    overlay.type = "button";
    overlay.setAttribute("aria-label", "Close navigation");
    document.body.appendChild(overlay);

    const setSidebar = (open) => {
        document.body.classList.toggle("sidebar-open", open);
        document.querySelector(".sidebar")?.classList.toggle("is-open", open);
        overlay.classList.toggle("is-open", open);
        menuButton.setAttribute("aria-expanded", String(open));
    };
    menuButton.addEventListener("click", () => setSidebar(!document.body.classList.contains("sidebar-open")));
    overlay.addEventListener("click", () => setSidebar(false));
    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape") setSidebar(false);
    });
}

function decoratePage(activePage) {
    const heading = document.querySelector(".page-heading, .page-header");
    if (heading && pageMeta[activePage] && !heading.querySelector(".eyebrow")) {
        const eyebrow = document.createElement("div");
        eyebrow.className = "eyebrow";
        eyebrow.textContent = pageMeta[activePage].label;
        heading.prepend(eyebrow);
    }

    const content = document.querySelector(".page-content");
    if (content && !content.querySelector(":scope > .console-footer")) {
        const footer = document.createElement("footer");
        footer.className = "console-footer";
        footer.innerHTML = `<span>ANOMALYSPIKE / RESEARCH PROTOTYPE</span><span>LOCAL ANALYSIS · YOUR DATA STAYS YOURS</span>`;
        content.appendChild(footer);
    }
}

function setupSidebarInteractions() {
    const closeButton = document.querySelector(".sidebar-close");
    if (closeButton) {
        closeButton.addEventListener("click", () => {
            document.body.classList.remove("sidebar-open");
            document.querySelector(".sidebar")?.classList.remove("is-open");
            document.querySelector(".sidebar-overlay")?.classList.remove("is-open");
            document.querySelector(".menu-toggle")?.setAttribute("aria-expanded", "false");
        });
    }

    const search = document.querySelector(".sidebar-search input");
    if (!search) return;
    const links = [...document.querySelectorAll(".sidebar-nav a")];
    const filterLinks = () => {
        const query = search.value.trim().toLowerCase();
        links.forEach((link) => {
            link.closest("li").hidden = query.length > 0 && !link.textContent.toLowerCase().includes(query);
        });
    };
    search.addEventListener("input", filterLinks);
    document.addEventListener("keydown", (event) => {
        if (event.key === "/" && !/input|textarea|select/i.test(document.activeElement?.tagName || "")) {
            event.preventDefault();
            search.focus();
        }
    });
}

async function loadSidebar(activePage) {
    decorateTopbar(activePage);
    decoratePage(activePage);

    const placeholder = document.getElementById("sidebar-placeholder");
    if (!placeholder) return;
    try {
        const res = await fetch("/static/partials/sidebar.html?v=" + Date.now());
        if (!res.ok) throw new Error(`Sidebar request failed (${res.status})`);
        placeholder.innerHTML = await res.text();
        const link = document.querySelector(`a[data-page="${activePage}"]`);
        if (link) {
            link.classList.add("active");
            link.setAttribute("aria-current", "page");
        }
        setupSidebarInteractions();
    } catch (error) {
        console.error("Unable to load navigation", error);
        placeholder.innerHTML = `<nav class="sidebar sidebar--fallback"><a href="/dashboard">AnomalySpike dashboard</a></nav>`;
    }
}
