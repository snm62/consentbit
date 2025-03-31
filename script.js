
document.addEventListener("DOMContentLoaded", function () {
    function toggleScrolling() {
        const banner = document.querySelector(".consebit-banner-div");
        if (banner) {
            const observer = new MutationObserver(() => {
                if (window.getComputedStyle(banner).display !== "none") {
                    document.body.style.overflow = "hidden"; // Disable scrolling
                } else {
                    document.body.style.overflow = ""; // Enable scrolling
                }
            });
            observer.observe(banner, { attributes: true, attributeFilter: ["style", "class"] });
        }
    }
    toggleScrolling();
});
