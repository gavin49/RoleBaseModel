// Handle dropdowns
function setupDropdowns() {
    // Close any open dropdowns when clicking outside
    document.addEventListener('click', (e) => {
        const dropdowns = document.querySelectorAll('.dropdown.show');
        dropdowns.forEach(dropdown => {
            if (!dropdown.contains(e.target)) {
                closeDropdown(dropdown);
            }
        });
    });

    // Setup all dropdowns in the application
    document.querySelectorAll('.dropdown').forEach(dropdown => {
        const toggle = dropdown.querySelector('.dropdown-toggle');
        const menu = dropdown.querySelector('.dropdown-menu');
        
        if (toggle && menu) {
            toggle.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                
                // Close other dropdowns
                document.querySelectorAll('.dropdown.show').forEach(other => {
                    if (other !== dropdown) {
                        closeDropdown(other);
                    }
                });
                
                // Toggle current dropdown
                const isOpen = dropdown.classList.contains('show');
                if (isOpen) {
                    closeDropdown(dropdown);
                } else {
                    openDropdown(dropdown);
                }
            });
        }
    });
}

function openDropdown(dropdown) {
    dropdown.classList.add('show');
    const toggle = dropdown.querySelector('.dropdown-toggle');
    const menu = dropdown.querySelector('.dropdown-menu');
    if (toggle) toggle.setAttribute('aria-expanded', 'true');
    if (menu) menu.classList.add('show');
}

function closeDropdown(dropdown) {
    dropdown.classList.remove('show');
    const toggle = dropdown.querySelector('.dropdown-toggle');
    const menu = dropdown.querySelector('.dropdown-menu');
    if (toggle) toggle.setAttribute('aria-expanded', 'false');
    if (menu) menu.classList.remove('show');
}

// Theme handling
function setupThemeToggle() {
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
        // Set initial state
        const currentTheme = localStorage.getItem('theme') || 'light';
        document.documentElement.setAttribute('data-theme', currentTheme);
        themeToggle.checked = currentTheme === 'dark';

        // Handle theme changes
        themeToggle.addEventListener('change', () => {
            const newTheme = themeToggle.checked ? 'dark' : 'light';
            document.documentElement.setAttribute('data-theme', newTheme);
            localStorage.setItem('theme', newTheme);
        });
    }
}

// Initialize all functionality when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    setupDropdowns();
    setupThemeToggle();
});