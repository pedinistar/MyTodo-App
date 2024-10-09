// script.js

document.querySelectorAll('.delete-btn').forEach(button => {
    button.addEventListener('click', function(e) {
        e.preventDefault();
        const todoId = this.getAttribute('data-id');
        const todoRow = this.closest('tr');

        // Apply fade-out class
        todoRow.classList.add('fade-out');

        // Wait for the animation to finish, then redirect to the delete route
        setTimeout(() => {
            window.location.href = `/delete/${todoId}`;
        }, 500); // Delay matches the CSS transition time
    });
});

