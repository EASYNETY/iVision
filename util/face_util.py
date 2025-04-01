import cv2
import numpy as np
import logging

def detect_faces(image_path):
    """
    Detect faces in an image using OpenCV
    
    Args:
        image_path (str): Path to the image file
        
    Returns:
        list: List of face rectangles (x, y, w, h)
    """
    try:
        # Load the image
        image = cv2.imread(image_path)
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Load the face cascade
        face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
        
        # Detect faces
        faces = face_cascade.detectMultiScale(gray, 1.1, 4)
        
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
            return None
        
        # Load the image
        image = cv2.imread(image_path)
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        
        # Extract the face
        x, y, w, h = faces[0]
        face_roi = gray[y:y+h, x:x+w]
        
        # Resize to standardize
        face_roi = cv2.resize(face_roi, (100, 100))
        
        # Apply histogram equalization to improve contrast
        face_roi = cv2.equalizeHist(face_roi)
        
        # Flatten the image to create a 1D feature vector
        face_vector = face_roi.flatten().astype(np.float32)
        
        # Apply normalization
        face_vector = face_vector / 255.0
        
        return face_vector
    except Exception as e:
        logging.error(f"Error generating face encoding: {e}")
        return None

def compare_faces(known_encoding, unknown_encoding, threshold=0.8):
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
        if known_encoding is None or unknown_encoding is None:
            return False
        
        # Calculate cosine similarity
        dot_product = np.dot(known_encoding, unknown_encoding)
        norm_a = np.linalg.norm(known_encoding)
        norm_b = np.linalg.norm(unknown_encoding)
        
        if norm_a == 0 or norm_b == 0:
            return False
        
        similarity = dot_product / (norm_a * norm_b)
        
        # Return True if the similarity is above the threshold
        return similarity > threshold
    except Exception as e:
        logging.error(f"Error comparing faces: {e}")
        return False
