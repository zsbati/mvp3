// /static/confirmDelete.js
function confirmDelete(username) {
    return confirm(`Really delete ${username}?`);
}

function confirmRevoke(form) { // Removed username argument
    if (confirm("Are you sure you want to revoke access?")) { // Simpler message
        form.submit();
    }
}
