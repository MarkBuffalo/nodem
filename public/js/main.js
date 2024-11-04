// public/js/main.js

document.addEventListener('DOMContentLoaded', function () {
    // Mobile menu toggle
    const menuButton = document.getElementById('mobile-menu-button');
    const navLinks = document.querySelector('.nav-list');

    menuButton.addEventListener('click', function () {
        navLinks.classList.toggle('active');
        menuButton.classList.toggle('active');
    });

    // Dropdown menu toggle
    const dropdownToggle = document.querySelector('.dropdown-toggle');
    const dropdownMenu = document.querySelector('.dropdown-menu');

    if (dropdownToggle) {
        dropdownToggle.addEventListener('click', function (e) {
            e.preventDefault();
            dropdownMenu.classList.toggle('show');
        });

        // Close dropdown when clicking outside
        window.addEventListener('click', function (e) {
            if (!dropdownMenu.contains(e.target) && !dropdownToggle.contains(e.target)) {
                dropdownMenu.classList.remove('show');
            }
        });
    }
});