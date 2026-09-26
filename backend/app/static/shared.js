async function loadSidebar(activePage) {
    const res = await fetch("/static/partials/sidebar.html?v=" + Date.now());
    const html = await res.text();
    document.getElementById("sidebar-placeholder").innerHTML = html;

    const link = document.querySelector(`a[data-page="${activePage}"]`);
    if (link) link.classList.add("active");
}
