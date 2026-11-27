document.addEventListener("DOMContentLoaded", function () {
  if (window.location.hash) {
    const msg = decodeURIComponent(window.location.hash.substring(1));
    const banner = document.getElementById("dom-banner");
    if (banner) {
      banner.textContent = "Status: " + msg;
    }
  }
});