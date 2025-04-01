import cv2
import numpy as np
import logging
import os

def detect_faces(image_path):
    """
    Detect faces in an image using OpenCV
    
    Args:
        image_path (str): Path to the image file
        
    Returns:
        list: List of face rectangles (x, y, w, h)
    """
    try:
        # Check if file exists
        import os
        if not os.path.exists(image_path):
            logging.error(f"Image file does not exist: {image_path}")
            return []
            
        # Load the image
        image = cv2.imread(image_path)
        
        # Check if image was loaded properly
        if image is None or image.size == 0:
            logging.error(f"Failed to load image or image is empty: {image_path}")
            return []
            
        # Convert to grayscale
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Load the face cascade
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        
        # Detect faces with more sensitive parameters
        faces = face_cascade.detectMultiScale(
            gray,
            scaleFactor=1.1,  # Scale factor for detection
            minNeighbors=5,   # Higher quality detection
            minSize=(30, 30)  # Minimum face size
        )
        
        # Log how many faces were found
        if len(faces) == 0:
            logging.warning(f"No faces detected in image: {image_path}")
        else:
            logging.info(f"Detected {len(faces)} faces in image: {image_path}")
            
        return faces
    except Exception as e:
        logging.error(f"Error detecting faces: {e}")
        return []

def get_face_encoding(image_path):
    """
    Get the face encoding for an image using OpenCV's LBPH
    
    Args:
        image_path (str): Path to the image file
        
    Returns:
        numpy.ndarray: Feature vector representing face characteristics
    """
    try:
        # Detect face first
        faces = detect_faces(image_path)
        if len(faces) == 0:
            logging.warning(f"No faces detected for encoding in: {image_path}")
            return None
            
        if len(faces) > 1:
            logging.warning(f"Multiple faces detected ({len(faces)}). Using the largest face.")
            # Sort faces by area (w*h) in descending order and take the largest
            faces = sorted(faces, key=lambda f: f[2] * f[3], reverse=True)
        
        # Load the image
        image = cv2.imread(image_path)
        if image is None:
            logging.error(f"Failed to load image for encoding: {image_path}")
            return None
            
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Extract the face
        x, y, w, h = faces[0]
        
        # Check if face region is within image bounds
        height, width = gray.shape
        if x < 0 or y < 0 or x+w > width or y+h > height:
            logging.warning("Face region out of image bounds. Adjusting.")
            x = max(0, x)
            y = max(0, y)
            w = min(width - x, w)
            h = min(height - y, h)
            
        # Extract the face ROI
        face_roi = gray[y:y+h, x:x+w]
        
        # Check if face ROI is valid
        if face_roi.size == 0:
            logging.error("Invalid face region with zero size")
            return None
        
        # Resize to standardize (100x100 resolution)
        face_roi = cv2.resize(face_roi, (100, 100))
        
        # Apply histogram equalization to improve contrast
        face_roi = cv2.equalizeHist(face_roi)
        
        # Apply Gaussian blur to reduce noise (3x3 kernel)
        face_roi = cv2.GaussianBlur(face_roi, (3, 3), 0)
        
        # Flatten the image to create a 1D feature vector
        face_vector = face_roi.flatten().astype(np.float32)
        
        # Apply normalization
        face_vector = face_vector / 255.0
        
        # Verify the shape of the vector
        if face_vector.shape[0] != 10000:  # Should be 100x100 = 10000
            logging.error(f"Unexpected face vector shape: {face_vector.shape}")
            return None
            
        # Log confirmation of successful encoding
        logging.info(f"Successfully encoded face with vector shape: {face_vector.shape}")
        
        return face_vector
    except Exception as e:
        logging.error(f"Error generating face encoding: {e}")
        return None

def compare_faces(known_encoding, unknown_encoding, threshold=0.95):
    """
    Compare faces to check if they match using cosine similarity
    
    Args:
        known_encoding (numpy.ndarray): Encoding of a known face
        unknown_encoding (numpy.ndarray): Encoding of an unknown face
        threshold (float): Threshold for face comparison (higher is stricter)
        
    Returns:
        bool: True if faces match, False otherwise
    """
    try:
        # Check if either encoding is None or empty
        if known_encoding is None or unknown_encoding is None:
            logging.warning("One of the face encodings is None")
            return False
            
        # Check if shapes match
        if known_encoding.shape != unknown_encoding.shape:
            logging.error(f"Shape mismatch: {known_encoding.shape} vs {unknown_encoding.shape}")
            return False
            
        # Check if encodings are empty
        if len(known_encoding) == 0 or len(unknown_encoding) == 0:
            logging.warning("Empty face encoding detected")
            return False
        
        # Calculate cosine similarity
        dot_product = np.dot(known_encoding, unknown_encoding)
        norm_a = np.linalg.norm(known_encoding)
        norm_b = np.linalg.norm(unknown_encoding)
        
        if norm_a == 0 or norm_b == 0:
            logging.warning("Zero norm detected in face encoding")
            return False
        
        similarity = dot_product / (norm_a * norm_b)
        
        # Log similarity score for debugging
        logging.info(f"Face similarity score: {similarity:.4f}, threshold: {threshold}")
        
        # Return True if the similarity is above the threshold
        return similarity > threshold
    except Exception as e:
        logging.error(f"Error comparing faces: {e}")
        return False
        
def crop_face_image(image_path, output_path=None, padding_percent=20):
    """
    Detect a face in an image and crop it with padding
    
    Args:
        image_path (str): Path to the input image
        output_path (str): Path to save the cropped image. If None, will use the input path
        padding_percent (int): Percentage of padding to add around the face
        
    Returns:
        str: Path to the cropped image or None if no face found
    """
    try:
        # Detect faces in the image
        faces = detect_faces(image_path)
        if len(faces) == 0:
            logging.warning(f"No faces detected for cropping in: {image_path}")
            return None
            
        if len(faces) > 1:
            logging.warning(f"Multiple faces detected ({len(faces)}). Using the largest face.")
            # Sort faces by area (w*h) in descending order and take the largest
            faces = sorted(faces, key=lambda f: f[2] * f[3], reverse=True)
        
        # Load the image
        image = cv2.imread(image_path)
        if image is None:
            logging.error(f"Failed to load image for cropping: {image_path}")
            return None
        
        # Get image dimensions
        height, width = image.shape[:2]
        
        # Get face coordinates
        x, y, w, h = faces[0]
        
        # Calculate padding
        padding_x = int(w * padding_percent / 100)
        padding_y = int(h * padding_percent / 100)
        
        # Calculate crop region with padding
        x1 = max(0, x - padding_x)
        y1 = max(0, y - padding_y)
        x2 = min(width, x + w + padding_x)
        y2 = min(height, y + h + padding_y)
        
        # Crop the image
        cropped = image[y1:y2, x1:x2]
        
        # Determine output path
        if output_path is None:
            filename, ext = os.path.splitext(image_path)
            output_path = f"{filename}_cropped{ext}"
        
        # Save the cropped image
        cv2.imwrite(output_path, cropped)
        logging.info(f"Face cropped and saved to: {output_path}")
        
        return output_path
    except Exception as e:
        logging.error(f"Error cropping face: {e}")
        return None
