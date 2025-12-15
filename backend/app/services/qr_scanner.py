"""QR Code scanning service for detecting URLs in email images."""

from __future__ import annotations

import io
import logging
from typing import List, Optional
from urllib.parse import urlparse

from PIL import Image
from pyzbar import pyzbar
from pyzbar.pyzbar import Decoded

logger = logging.getLogger(__name__)


class QRCodeScanner:
    """Scans images for QR codes and extracts URLs."""

    @staticmethod
    def scan_image_bytes(image_data: bytes) -> List[str]:
        """Scan image bytes for QR codes and return any URLs found.
        
        Args:
            image_data: Raw image bytes (PNG, JPEG, etc.)
            
        Returns:
            List of URLs found in QR codes
        """
        urls: List[str] = []
        
        try:
            # Open image with PIL
            image = Image.open(io.BytesIO(image_data))
            
            # Decode all barcodes/QR codes in the image
            decoded_objects: List[Decoded] = pyzbar.decode(image)
            
            for obj in decoded_objects:
                # Get the data from the QR/barcode
                try:
                    data = obj.data.decode('utf-8')
                except UnicodeDecodeError:
                    continue
                
                # Check if it looks like a URL
                url = QRCodeScanner._extract_url(data)
                if url:
                    urls.append(url)
                    logger.info(f"Found URL in QR code: {url}")
                    
        except Exception as e:
            logger.debug(f"Failed to scan image for QR codes: {e}")
        
        return urls

    @staticmethod
    def _extract_url(data: str) -> Optional[str]:
        """Extract and validate URL from QR code data.
        
        Args:
            data: Raw data from QR code
            
        Returns:
            Valid URL or None
        """
        data = data.strip()
        
        # Must start with http:// or https://
        if not data.startswith(('http://', 'https://')):
            return None
        
        # Validate with urlparse
        try:
            parsed = urlparse(data)
            
            # Must have a valid domain
            if not parsed.netloc:
                return None
            
            # Domain must have at least one dot (or be localhost)
            if '.' not in parsed.netloc and parsed.netloc.lower() != 'localhost':
                return None
            
            return data
        except Exception:
            return None


def scan_attachments_for_qr_urls(attachments: List[dict]) -> List[str]:
    """Scan email attachments for QR codes containing URLs.
    
    Args:
        attachments: List of attachment dicts with 'content_type' and 'data' (base64 or bytes)
        
    Returns:
        List of URLs found in QR codes
    """
    import base64
    
    scanner = QRCodeScanner()
    all_urls: List[str] = []
    
    for attachment in attachments:
        content_type = attachment.get('content_type', '')
        
        # Only scan image attachments
        if not content_type.startswith('image/'):
            continue
        
        # Get image data
        data = attachment.get('data') or attachment.get('content')
        if not data:
            continue
        
        # Decode base64 if needed
        if isinstance(data, str):
            try:
                data = base64.b64decode(data)
            except Exception:
                continue
        
        # Scan for QR codes
        urls = scanner.scan_image_bytes(data)
        all_urls.extend(urls)
    
    return all_urls
