// Dark mode toggle
document.addEventListener("DOMContentLoaded", function () {
    const toggleDarkMode = document.getElementById("darkModeToggle");

    // Load user preference
    if (localStorage.getItem("dark-mode") === "enabled") {
        document.body.classList.add("dark-mode");
    }

    toggleDarkMode.addEventListener("click", function () {
        document.body.classList.toggle("dark-mode");
        
        // Save user preference
        if (document.body.classList.contains("dark-mode")) {
            localStorage.setItem("dark-mode", "enabled");
        } else {
            localStorage.setItem("dark-mode", "disabled");
        }
    });
});
