document.addEventListener('DOMContentLoaded', function() {
    const logoInput = document.getElementById('logo');
    const currentLogo = document.querySelector('.current-logo');

    logoInput.addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file) {
            if (file.size > 2 * 1024 * 1024) {
                alert('File size must be less than 2MB');
                return;
            }

            const reader = new FileReader();
            reader.onload = function(e) {
                currentLogo.innerHTML = `<img src="${e.target.result}" alt="Organization Logo">`;
            };
            reader.readAsDataURL(file);
        }
    });
});