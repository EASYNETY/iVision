document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements - Register
    const registerForm = document.getElementById('registerForm');
    const fullName = document.getElementById('fullName');
    const registerImage = document.getElementById('registerImage');
    const registerPreviewImg = document.getElementById('registerPreviewImg');
    const registerPlaceholder = document.getElementById('registerPlaceholder');
    const registerBtn = document.getElementById('registerBtn');
    const registerAlert = document.getElementById('registerAlert');
    
    // DOM Elements - Identify
    const identifyForm = document.getElementById('identifyForm');
    const identifyImage = document.getElementById('identifyImage');
    const identifyPreviewImg = document.getElementById('identifyPreviewImg');
    const identifyPlaceholder = document.getElementById('identifyPlaceholder');
    const identifyBtn = document.getElementById('identifyBtn');
    const identifyAlert = document.getElementById('identifyAlert');
    
    // DOM Elements - Manage
    const usersList = document.getElementById('usersList');
    const refreshUsersBtn = document.getElementById('refreshUsersBtn');
    const resetDatabaseBtn = document.getElementById('resetDatabaseBtn');
    const manageAlert = document.getElementById('manageAlert');
    
    // Tab management
    const operationTabs = document.querySelectorAll('#operationTabs button');
    operationTabs.forEach(tab => {
        tab.addEventListener('click', function() {
            // Hide all alerts when switching tabs
            hideAlert(registerAlert);
            hideAlert(identifyAlert);
            hideAlert(manageAlert);
            
            // If switching to manage tab, refresh users list
            if (this.id === 'manage-tab') {
                fetchUsers();
            }
        });
    });
    
    // Handle image preview for register
    registerImage.addEventListener('change', function(e) {
        previewImage(e, registerPreviewImg, registerPlaceholder);
    });
    
    // Handle image preview for identify
    identifyImage.addEventListener('change', function(e) {
        previewImage(e, identifyPreviewImg, identifyPlaceholder);
    });
    
    // Handle register form submission
    registerForm.addEventListener('submit', function(e) {
        e.preventDefault();
        registerUser();
    });
    
    // Handle identify form submission
    identifyForm.addEventListener('submit', function(e) {
        e.preventDefault();
        identifyFace();
    });
    
    // Handle refresh users button
    refreshUsersBtn.addEventListener('click', fetchUsers);
    
    // Handle reset database button
    resetDatabaseBtn.addEventListener('click', function() {
        if (confirm('Are you sure you want to reset the database? This will remove all registered users.')) {
            resetDatabase();
        }
    });
    
    // Fetch users when manage tab is first opened
    document.getElementById('manage-tab').addEventListener('shown.bs.tab', fetchUsers);
    
    // Function to preview uploaded image
    function previewImage(event, previewImg, placeholder) {
        const file = event.target.files[0];
        if (file) {
            const reader = new FileReader();
            
            reader.onload = function(e) {
                previewImg.src = e.target.result;
                previewImg.classList.remove('d-none');
                placeholder.classList.add('d-none');
            };
            
            reader.readAsDataURL(file);
        } else {
            previewImg.classList.add('d-none');
            placeholder.classList.remove('d-none');
        }
    }
    
    // Function to register a user
    function registerUser() {
        if (!fullName.value.trim()) {
            showAlert(registerAlert, 'Please enter a full name', 'danger');
            return;
        }
        
        if (!registerImage.files || registerImage.files.length === 0) {
            showAlert(registerAlert, 'Please select an image', 'danger');
            return;
        }
        
        // Validate consent checkboxes
        const biometricConsent = document.getElementById('biometricConsent');
        const dataStorageConsent = document.getElementById('dataStorageConsent');
        const termsAccepted = document.getElementById('termsAccepted');
        
        if (!biometricConsent.checked || !dataStorageConsent.checked || !termsAccepted.checked) {
            showAlert(registerAlert, 'You must accept all consent checkboxes to continue', 'danger');
            return;
        }
        
        // Create form data with all form fields
        const formData = new FormData(registerForm);
        
        // Set button to loading state
        setButtonLoading(registerBtn, true);
        
        // Send request to server
        fetch('/register', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showAlert(registerAlert, data.message, 'success');
                registerForm.reset();
                registerPreviewImg.classList.add('d-none');
                registerPlaceholder.classList.remove('d-none');
            } else {
                showAlert(registerAlert, data.message, 'danger');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showAlert(registerAlert, 'An error occurred. Please try again.', 'danger');
        })
        .finally(() => {
            setButtonLoading(registerBtn, false);
        });
    }
    
    // Function to identify a face
    function identifyFace() {
        if (!identifyImage.files || identifyImage.files.length === 0) {
            showAlert(identifyAlert, 'Please select an image', 'danger');
            return;
        }
        
        // Create form data
        const formData = new FormData();
        formData.append('image', identifyImage.files[0]);
        
        // Set button to loading state
        setButtonLoading(identifyBtn, true);
        
        // Send request to server
        fetch('/identify', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showAlert(identifyAlert, data.message, 'success');
            } else {
                showAlert(identifyAlert, data.message, 'warning');
            }
        })
        .catch(error => {
            console.error('Error:', error);
            showAlert(identifyAlert, 'An error occurred. Please try again.', 'danger');
        })
        .finally(() => {
            setButtonLoading(identifyBtn, false);
        });
    }
    
    // Function to fetch registered users
    function fetchUsers() {
        setButtonLoading(refreshUsersBtn, true);
        
        fetch('/users')
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateUsersList(data.users);
                } else {
                    showAlert(manageAlert, 'Error fetching users', 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert(manageAlert, 'An error occurred while fetching users', 'danger');
            })
            .finally(() => {
                setButtonLoading(refreshUsersBtn, false);
            });
    }
    
    // Function to update users list
    function updateUsersList(users) {
        usersList.innerHTML = '';
        
        if (users.length === 0) {
            usersList.innerHTML = `
                <tr>
                    <td colspan="3" class="text-center">No users registered</td>
                </tr>
            `;
            return;
        }
        
        // Update the table headers
        const tableHeader = document.querySelector('#manage table thead tr');
        tableHeader.innerHTML = `
            <th>Name</th>
            <th>Email</th>
            <th>Registration Date</th>
        `;
        
        users.forEach(user => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${user.name || ''}</td>
                <td>${user.email || 'N/A'}</td>
                <td>${user.registration_date || 'N/A'}</td>
            `;
            row.style.cursor = 'pointer';
            row.addEventListener('click', () => {
                if (user.id) {
                    window.location.href = `/user/${user.id}`;
                }
            });
            usersList.appendChild(row);
        });
    }
    
    // Function to reset database
    function resetDatabase() {
        setButtonLoading(resetDatabaseBtn, true);
        
        fetch('/reset', {
            method: 'POST'
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert(manageAlert, data.message, 'success');
                    fetchUsers();
                } else {
                    showAlert(manageAlert, 'Error resetting database', 'danger');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                showAlert(manageAlert, 'An error occurred while resetting the database', 'danger');
            })
            .finally(() => {
                setButtonLoading(resetDatabaseBtn, false);
            });
    }
    
    // Utility function to show alert
    function showAlert(alertElement, message, type) {
        alertElement.textContent = message;
        alertElement.className = `alert alert-${type}`;
        alertElement.classList.remove('d-none');
        
        // Auto hide after 5 seconds
        setTimeout(() => {
            hideAlert(alertElement);
        }, 5000);
    }
    
    // Utility function to hide alert
    function hideAlert(alertElement) {
        alertElement.classList.add('d-none');
    }
    
    // Utility function to set button loading state
    function setButtonLoading(button, isLoading) {
        if (isLoading) {
            const originalText = button.innerHTML;
            button.setAttribute('data-original-text', originalText);
            button.innerHTML = `
                <span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span>
                Loading...
            `;
            button.disabled = true;
        } else {
            const originalText = button.getAttribute('data-original-text');
            button.innerHTML = originalText;
            button.disabled = false;
        }
    }
    
    // Initial users fetch
    if (document.getElementById('manage-tab').classList.contains('active')) {
        fetchUsers();
    }
});
