document.addEventListener('DOMContentLoaded', function() {
    const navItems = document.querySelectorAll('.nav-item');

    navItems.forEach(item => {
        const navLink = item.querySelector('.nav-link');
        
        navLink.addEventListener('click', function(e) {
            e.preventDefault();
            
            // If clicking the same item that's already active, remove active class
            if (item.classList.contains('active')) {
                item.classList.remove('active');
            } else {
                // Remove active class from all nav items
                navItems.forEach(ni => ni.classList.remove('active'));
                // Add active class to clicked item
                item.classList.add('active');
            }
        });
    });
});