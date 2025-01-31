function confirmRevokeAccess() {
    const teacherUsername = document.getElementById('teacher').value;
    const studentUsername = document.getElementById('student').value;
    return confirm(`Really revoke access for ${teacherUsername} from ${studentUsername}?`);
}
