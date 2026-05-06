(function () {
    var KEY = "theme";
    var body = document.body;
    var btn = document.getElementById("theme-toggle");

    function applyFromStorage() {
        try {
            var stored = localStorage.getItem(KEY);
            if (stored === "dark") {
                body.classList.add("dark");
            } else if (stored === "light") {
                body.classList.remove("dark");
            } else {
                body.classList.add("dark");
            }
        } catch (e) {
            body.classList.add("dark");
        }
        syncButton();
    }

    function syncButton() {
        if (!btn) {
            return;
        }
        var dark = body.classList.contains("dark");
        btn.setAttribute("aria-pressed", dark ? "true" : "false");
    }

    applyFromStorage();

    if (btn) {
        btn.addEventListener("click", function () {
            var nextDark = !body.classList.contains("dark");
            body.classList.toggle("dark", nextDark);
            try {
                localStorage.setItem(KEY, nextDark ? "dark" : "light");
            } catch (e) {
                /* ignore */
            }
            syncButton();
        });
    }
})();
