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
        
        // Explicitly add checkbox values since some browsers may not include unchecked boxes
        formData.set('has_biometric_consent', biometricConsent.checked ? 'true' : 'false');
        formData.set('has_data_storage_consent', dataStorageConsent.checked ? 'true' : 'false');
        formData.set('terms_accepted', termsAccepted.checked ? 'true' : 'false');
        
        // For debugging
        console.log("Biometric consent:", biometricConsent.checked);
        console.log("Data storage consent:", dataStorageConsent.checked);
        console.log("Terms accepted:", termsAccepted.checked);
        
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
    
    // Function to identify a face with matrix animation
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
        
        // Show matrix animation
        showMatrixAnimation();
        
        // Send request to server
        fetch('/identify', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            // Complete the matrix animation with the result
            if (data.success) {
                completeMatrixAnimation(data.user, true);
                setTimeout(() => {
                    showAlert(identifyAlert, data.message, 'success');
                }, 3000); // delay showing the alert until animation is almost done
            } else {
                completeMatrixAnimation(null, false);
                setTimeout(() => {
                    showAlert(identifyAlert, data.message, 'warning');
                }, 3000);
            }
        })
        .catch(error => {
            console.error('Error:', error);
            completeMatrixAnimation(null, false);
            setTimeout(() => {
                showAlert(identifyAlert, 'An error occurred. Please try again.', 'danger');
            }, 3000);
        })
        .finally(() => {
            setButtonLoading(identifyBtn, false);
        });
    }
    
    // Matrix animation functions
    const matrixOverlay = document.getElementById('matrixOverlay');
    const matrixGrid = document.getElementById('matrixGrid');
    const matrixStatusText = document.getElementById('matrixStatusText');
    const matrixProgressBar = document.getElementById('matrixProgressBar');
    const matrixResult = document.getElementById('matrixResult');
    const resultText = document.getElementById('resultText');
    const matchDetails = document.getElementById('matchDetails');
    const binaryBackground = document.getElementById('binaryBackground');
    const closeMatrix = document.getElementById('closeMatrix');
    
    // Will store user images from the database
    let userProfileImages = [];
    
    // Animation status messages
    const statusMessages = [
        'Initializing facial recognition vectors...',
        'Extracting facial landmarks...',
        'Calculating feature distances...',
        'Normalizing biometric data...',
        'Searching database for matches...',
        'Running advanced recognition algorithms...',
        'Verifying identity matches...',
        'Cross-referencing with known patterns...',
        'Finalizing analysis results...'
    ];
    
    function showMatrixAnimation() {
        // Clear previous animation state
        matrixGrid.innerHTML = '';
        matrixProgressBar.style.width = '0%';
        matrixResult.style.display = 'none';
        
        // Generate binary background for matrix effect
        generateBinaryBackground();
        
        // Show the overlay with a loading message
        matrixOverlay.style.display = 'flex';
        matrixStatusText.textContent = 'Loading database imagery...';
        
        // Fetch user images for the animation
        fetchUserImagesForMatrix().then(() => {
            // Create grid cells with actual user images or fallback images
            createMatrixGrid();
            
            // Start progress animation
            runMatrixAnimation();
        });
    }
    
    // Function to fetch user images for the matrix animation
    function fetchUserImagesForMatrix() {
        return fetch('/users?include_images=true')
            .then(response => response.json())
            .then(data => {
                if (data.success && data.users && data.users.length > 0) {
                    // Extract image URLs from the users data
                    userProfileImages = data.users
                        .filter(user => user.image_url)
                        .map(user => user.image_url);
                    
                    // If we don't have enough images, add some fallback images
                    if (userProfileImages.length < 4) {
                        const fallbackImages = [
                            '/static/img/placeholders/face1.svg',
                            '/static/img/placeholders/face2.svg',
                            '/static/img/placeholders/face3.svg',
                            '/static/img/placeholders/face4.svg'
                        ];
                        
                        // Add fallback images to make sure we have at least 4 images
                        userProfileImages = [...userProfileImages, ...fallbackImages.slice(0, 4 - userProfileImages.length)];
                    }
                } else {
                    // Use fallback images if no users are available
                    userProfileImages = [
                        '/static/img/placeholders/face1.svg',
                        '/static/img/placeholders/face2.svg',
                        '/static/img/placeholders/face3.svg', 
                        '/static/img/placeholders/face4.svg',
                        '/static/img/placeholders/face5.svg',
                        '/static/img/placeholders/face6.svg'
                    ];
                }
            })
            .catch(error => {
                console.error('Error fetching user images:', error);
                // Use fallback images in case of an error
                userProfileImages = [
                    '/static/img/placeholders/face1.svg',
                    '/static/img/placeholders/face2.svg',
                    '/static/img/placeholders/face3.svg',
                    '/static/img/placeholders/face4.svg'
                ];
            });
    }
    
    // Function to create the matrix grid cells
    function createMatrixGrid() {
        // Create grid cells with images
        for (let i = 0; i < 12; i++) {
            const cell = document.createElement('div');
            cell.className = 'matrix-cell';
            
            const img = document.createElement('img');
            img.src = userProfileImages[i % userProfileImages.length];
            img.alt = 'Face image';
            
            const scanLine = document.createElement('div');
            scanLine.className = 'scan-line';
            
            cell.appendChild(img);
            cell.appendChild(scanLine);
            matrixGrid.appendChild(cell);
        }
    }
    
    function runMatrixAnimation() {
        let progress = 0;
        let messageIndex = 0;
        
        // Update status message periodically
        matrixStatusText.textContent = statusMessages[0];
        
        const messageInterval = setInterval(() => {
            messageIndex = (messageIndex + 1) % statusMessages.length;
            matrixStatusText.textContent = statusMessages[messageIndex];
        }, 1500);
        
        // Highlight random cells to simulate processing
        const highlightInterval = setInterval(() => {
            // Remove all highlights
            document.querySelectorAll('.matrix-cell.highlight').forEach(cell => {
                cell.classList.remove('highlight');
            });
            
            // Add new random highlights
            const cells = document.querySelectorAll('.matrix-cell');
            const randomCell1 = cells[Math.floor(Math.random() * cells.length)];
            const randomCell2 = cells[Math.floor(Math.random() * cells.length)];
            
            randomCell1.classList.add('highlight');
            randomCell2.classList.add('highlight');
        }, 400);
        
        // Update progress bar
        const progressInterval = setInterval(() => {
            progress += 1;
            matrixProgressBar.style.width = `${progress}%`;
            
            // If we've reached 100%, clear the intervals
            if (progress >= 100) {
                clearInterval(messageInterval);
                clearInterval(highlightInterval);
                clearInterval(progressInterval);
            }
        }, 100);
    }
    
    function completeMatrixAnimation(userData, isSuccess) {
        // Ensure progress bar is complete
        matrixProgressBar.style.width = '100%';
        
        // Show result section
        matrixResult.style.display = 'block';
        
        if (isSuccess && userData) {
            resultText.textContent = 'MATCH FOUND';
            resultText.style.color = '#00ff00';
            
            // Display user details
            matchDetails.innerHTML = `
                <div class="mt-3">
                    <p><strong>Name:</strong> ${userData.full_name}</p>
                    <p><strong>ID:</strong> ${userData.user_id}</p>
                    <p class="text-success">Identity verification successful</p>
                </div>
            `;
        } else {
            resultText.textContent = 'NO MATCH FOUND';
            resultText.style.color = '#ff3333';
            
            matchDetails.innerHTML = `
                <div class="mt-3">
                    <p class="text-danger">Identity verification failed</p>
                    <p>No matching records found in the database.</p>
                </div>
            `;
        }
        
        // Hide matrix overlay after a delay
        setTimeout(() => {
            hideMatrixAnimation();
        }, 5000);
    }
    
    function hideMatrixAnimation() {
        matrixOverlay.style.display = 'none';
    }
    
    function generateBinaryBackground() {
        binaryBackground.innerHTML = '';
        const chars = '01';
        let html = '';
        
        for (let i = 0; i < 1000; i++) {
            html += chars.charAt(Math.floor(Math.random() * chars.length));
            if (i % 50 === 0) html += '<br>';
        }
        
        binaryBackground.innerHTML = html;
    }
    
    // Add event listener to close button
    closeMatrix.addEventListener('click', hideMatrixAnimation);
    
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
