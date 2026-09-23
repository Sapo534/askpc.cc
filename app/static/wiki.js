// Wiki Hover Tooltip Script
(function() {
    const popover = document.getElementById('wiki-popover');
    const popTerm = document.getElementById('wiki-popover-term');
    const popCat = document.getElementById('wiki-popover-cat');
    const popSummary = document.getElementById('wiki-popover-summary');
    const cache = {};
    let activeLink = null;

    if (!popover) return;

    document.addEventListener('mouseover', async function(e) {
        const link = e.target.closest('a[href*="/wiki/"]');
        if (!link || link.getAttribute('href') === '/wiki') return;

        activeLink = link;
        const parts = link.pathname.split('/').filter(Boolean);
        if (parts.length < 2) return;
        const slug = parts[1].toLowerCase().trim();

        // Position popover right under the link
        const rect = link.getBoundingClientRect();
        let top = rect.bottom + 8;
        let left = rect.left;
        if (left + 330 > window.innerWidth) left = window.innerWidth - 340;
        if (left < 10) left = 10;

        popover.style.top = top + 'px';
        popover.style.left = left + 'px';

        // Check local memory cache first
        if (cache[slug]) {
            render(cache[slug]);
            return;
        }

        try {
            const res = await fetch('/api/wiki/' + encodeURIComponent(slug) + '/summary');
            if (!res.ok) throw new Error("Term not found");
            const data = await res.json();
            cache[slug] = data;
            if (activeLink === link) render(data);
        } catch (err) {
            popover.style.display = 'none';
        }
    });

    document.addEventListener('mouseout', function(e) {
        const link = e.target.closest('a[href*="/wiki/"]');
        if (link && link === activeLink) {
            activeLink = null;
            popover.style.display = 'none';
        }
    });

    function render(data) {
        popTerm.textContent = data.term;
        popCat.textContent = data.category || 'WIKI';
        popSummary.textContent = data.summary;
        popover.style.display = 'block';
    }
})();
