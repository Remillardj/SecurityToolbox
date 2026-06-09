"""
Email Parser Module
Parses .eml and .msg email files for analysis.
"""

import email
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
import base64
import quopri
import re
from datetime import datetime


@dataclass
class Attachment:
    """Represents an email attachment."""
    filename: str
    content_type: str
    size: int
    content: bytes
    md5: str = ""
    sha256: str = ""
    
    def __post_init__(self):
        import hashlib
        if self.content:
            self.md5 = hashlib.md5(self.content).hexdigest()
            self.sha256 = hashlib.sha256(self.content).hexdigest()


@dataclass
class ParsedEmail:
    """Represents a fully parsed email."""
    # Basic headers
    subject: str = ""
    from_address: str = ""
    from_name: str = ""
    to_addresses: List[str] = field(default_factory=list)
    cc_addresses: List[str] = field(default_factory=list)
    bcc_addresses: List[str] = field(default_factory=list)
    reply_to: str = ""
    date: Optional[datetime] = None
    message_id: str = ""
    
    # Content
    body_text: str = ""
    body_html: str = ""
    
    # Attachments
    attachments: List[Attachment] = field(default_factory=list)
    
    # Headers (all)
    headers: Dict[str, List[str]] = field(default_factory=dict)
    raw_headers: str = ""
    
    # Authentication headers
    received_headers: List[str] = field(default_factory=list)
    authentication_results: str = ""
    received_spf: str = ""
    dkim_signature: str = ""
    dmarc_result: str = ""
    
    # Metadata
    file_path: str = ""
    file_size: int = 0
    parse_errors: List[str] = field(default_factory=list)


class EmailParser:
    """
    Parser for email files (.eml, .msg formats).
    Extracts all components including headers, body, attachments.
    """
    
    def __init__(self):
        self.supported_extensions = ['.eml', '.msg', '.txt']
    
    def parse(self, file_path: str) -> ParsedEmail:
        """
        Parse an email file and extract all components.
        
        Args:
            file_path: Path to the email file
            
        Returns:
            ParsedEmail object with all extracted data
        """
        path = Path(file_path)
        
        if not path.exists():
            raise FileNotFoundError(f"Email file not found: {file_path}")
        
        ext = path.suffix.lower()
        
        if ext == '.msg':
            return self._parse_msg(path)
        else:
            # Treat as .eml format (RFC 5322)
            return self._parse_eml(path)
    
    def _parse_eml(self, path: Path) -> ParsedEmail:
        """Parse an EML format email."""
        parsed = ParsedEmail()
        parsed.file_path = str(path)
        parsed.file_size = path.stat().st_size
        
        try:
            with open(path, 'rb') as f:
                raw_content = f.read()
            
            # Store raw headers
            header_end = raw_content.find(b'\n\n')
            if header_end == -1:
                header_end = raw_content.find(b'\r\n\r\n')
            if header_end != -1:
                parsed.raw_headers = raw_content[:header_end].decode('utf-8', errors='replace')
            
            # Parse email
            msg = BytesParser(policy=policy.default).parsebytes(raw_content)
            
            # Extract basic headers
            parsed.subject = self._decode_header(msg.get('Subject', ''))
            parsed.message_id = msg.get('Message-ID', '')
            parsed.reply_to = msg.get('Reply-To', '')
            
            # Parse From address
            from_header = msg.get('From', '')
            parsed.from_address, parsed.from_name = self._parse_address(from_header)
            
            # Parse To addresses
            to_header = msg.get('To', '')
            if to_header:
                parsed.to_addresses = self._parse_address_list(to_header)
            
            # Parse CC addresses
            cc_header = msg.get('Cc', '')
            if cc_header:
                parsed.cc_addresses = self._parse_address_list(cc_header)
            
            # Parse BCC addresses
            bcc_header = msg.get('Bcc', '')
            if bcc_header:
                parsed.bcc_addresses = self._parse_address_list(bcc_header)
            
            # Parse date
            date_header = msg.get('Date', '')
            if date_header:
                parsed.date = self._parse_date(date_header)
            
            # Extract all headers
            for key in msg.keys():
                if key not in parsed.headers:
                    parsed.headers[key] = []
                parsed.headers[key].append(str(msg.get(key, '')))
            
            # Authentication headers
            parsed.received_headers = msg.get_all('Received', [])
            parsed.authentication_results = msg.get('Authentication-Results', '')
            parsed.received_spf = msg.get('Received-SPF', '')
            parsed.dkim_signature = msg.get('DKIM-Signature', '')
            
            # Look for DMARC in Authentication-Results
            auth_results = msg.get('Authentication-Results', '')
            if 'dmarc=' in auth_results.lower():
                dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
                if dmarc_match:
                    parsed.dmarc_result = dmarc_match.group(1)
            
            # Extract body
            parsed.body_text, parsed.body_html = self._extract_body(msg)
            
            # Extract attachments
            parsed.attachments = self._extract_attachments(msg)
            
        except Exception as e:
            parsed.parse_errors.append(f"Parse error: {str(e)}")
        
        return parsed
    
    def _parse_msg(self, path: Path) -> ParsedEmail:
        """Parse a Microsoft MSG format email."""
        parsed = ParsedEmail()
        parsed.file_path = str(path)
        parsed.file_size = path.stat().st_size
        
        try:
            # Try to use extract_msg library
            import extract_msg
            
            msg = extract_msg.Message(str(path))
            
            parsed.subject = msg.subject or ""
            parsed.from_address = msg.sender or ""
            parsed.to_addresses = [msg.to] if msg.to else []
            parsed.cc_addresses = [msg.cc] if msg.cc else []
            parsed.date = msg.date
            parsed.message_id = msg.messageId or ""
            
            parsed.body_text = msg.body or ""
            parsed.body_html = msg.htmlBody or ""
            
            # Extract attachments
            for att in msg.attachments:
                if hasattr(att, 'data') and att.data:
                    attachment = Attachment(
                        filename=att.longFilename or att.shortFilename or "unknown",
                        content_type=att.mimetype or "application/octet-stream",
                        size=len(att.data),
                        content=att.data
                    )
                    parsed.attachments.append(attachment)
            
            msg.close()
            
        except ImportError:
            parsed.parse_errors.append(
                "extract-msg library not installed. Install with: pip install extract-msg"
            )
        except Exception as e:
            parsed.parse_errors.append(f"MSG parse error: {str(e)}")
        
        return parsed
    
    def _decode_header(self, header_value: str) -> str:
        """Decode email header value handling encoded words."""
        if not header_value:
            return ""
        
        try:
            from email.header import decode_header
            
            decoded_parts = []
            for part, charset in decode_header(header_value):
                if isinstance(part, bytes):
                    charset = charset or 'utf-8'
                    try:
                        decoded_parts.append(part.decode(charset, errors='replace'))
                    except (LookupError, UnicodeDecodeError):
                        decoded_parts.append(part.decode('utf-8', errors='replace'))
                else:
                    decoded_parts.append(part)
            
            return ''.join(decoded_parts)
        except Exception:
            return str(header_value)
    
    def _parse_address(self, addr_string: str) -> Tuple[str, str]:
        """Parse an email address string into (email, name) tuple."""
        if not addr_string:
            return ("", "")
        
        from email.utils import parseaddr
        name, email_addr = parseaddr(addr_string)
        return (email_addr, self._decode_header(name))
    
    def _parse_address_list(self, addr_string: str) -> List[str]:
        """Parse a comma-separated list of email addresses."""
        if not addr_string:
            return []
        
        from email.utils import getaddresses
        addresses = getaddresses([addr_string])
        return [addr for name, addr in addresses if addr]
    
    def _parse_date(self, date_string: str) -> Optional[datetime]:
        """Parse email date header."""
        from email.utils import parsedate_to_datetime
        try:
            return parsedate_to_datetime(date_string)
        except Exception:
            return None
    
    def _extract_body(self, msg: EmailMessage) -> Tuple[str, str]:
        """Extract plain text and HTML body from email."""
        text_body = ""
        html_body = ""
        
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Skip attachments
                if "attachment" in content_disposition:
                    continue
                
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or 'utf-8'
                        try:
                            decoded = payload.decode(charset, errors='replace')
                        except (LookupError, UnicodeDecodeError):
                            decoded = payload.decode('utf-8', errors='replace')
                        
                        if content_type == "text/plain" and not text_body:
                            text_body = decoded
                        elif content_type == "text/html" and not html_body:
                            html_body = decoded
                except Exception:
                    continue
        else:
            content_type = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or 'utf-8'
                    try:
                        decoded = payload.decode(charset, errors='replace')
                    except (LookupError, UnicodeDecodeError):
                        decoded = payload.decode('utf-8', errors='replace')
                    
                    if content_type == "text/plain":
                        text_body = decoded
                    elif content_type == "text/html":
                        html_body = decoded
            except Exception:
                pass
        
        return text_body, html_body
    
    def _extract_attachments(self, msg: EmailMessage) -> List[Attachment]:
        """Extract attachments from email."""
        attachments = []
        
        if not msg.is_multipart():
            return attachments
        
        for part in msg.walk():
            content_disposition = str(part.get("Content-Disposition", ""))
            
            if "attachment" in content_disposition or part.get_filename():
                filename = part.get_filename()
                if filename:
                    filename = self._decode_header(filename)
                else:
                    filename = "unknown_attachment"
                
                try:
                    content = part.get_payload(decode=True)
                    if content:
                        attachment = Attachment(
                            filename=filename,
                            content_type=part.get_content_type(),
                            size=len(content),
                            content=content
                        )
                        attachments.append(attachment)
                except Exception:
                    continue
        
        return attachments
    
    def parse_from_string(self, email_content: str) -> ParsedEmail:
        """Parse email from string content."""
        parsed = ParsedEmail()
        
        try:
            msg = BytesParser(policy=policy.default).parsebytes(
                email_content.encode('utf-8')
            )
            
            # Use same extraction logic
            parsed.subject = self._decode_header(msg.get('Subject', ''))
            parsed.message_id = msg.get('Message-ID', '')
            
            from_header = msg.get('From', '')
            parsed.from_address, parsed.from_name = self._parse_address(from_header)
            
            to_header = msg.get('To', '')
            if to_header:
                parsed.to_addresses = self._parse_address_list(to_header)
            
            parsed.body_text, parsed.body_html = self._extract_body(msg)
            parsed.attachments = self._extract_attachments(msg)
            
            for key in msg.keys():
                if key not in parsed.headers:
                    parsed.headers[key] = []
                parsed.headers[key].append(str(msg.get(key, '')))
            
        except Exception as e:
            parsed.parse_errors.append(f"String parse error: {str(e)}")
        
        return parsed

