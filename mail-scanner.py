"""
title: IMAP Email Scanner
author: Stefan Ostermann
author_url: https://github.com/soster/
git_url: https://github.com/soster/openwebui-ai-tools/mail-scanner.py
description: A tool that fetches emails from an IMAP folder and includes them in the LLM's context.
version: 0.0.1
license: MIT
"""

from typing import Callable, Any, Optional
from pydantic import BaseModel, Field, ValidationError, ConfigDict
import imaplib
import email
from email.policy import default
import asyncio
import unittest
from datetime import datetime, timezone
import logging
import re


class EventEmitter:
    def __init__(self, event_emitter: Callable[[dict], Any] = None):
        self.event_emitter = event_emitter

    async def progress_update(self, description: str):
        await self.emit(description)

    async def error_update(self, description: str):
        await self.emit(description, "error", True)

    async def success_update(self, description: str):
        await self.emit(description, "success", True)

    async def emit(
        self,
        description: str = "Unknown State",
        status: str = "in_progress",
        done: bool = False,
    ):
        if self.event_emitter:
            await self.event_emitter(
                {
                    "type": "status",
                    "data": {
                        "status": status,
                        "description": description,
                        "done": done,
                    },
                }
            )


class Tools:
    class Valves(BaseModel):
        model_config = ConfigDict(arbitrary_types_allowed=True)

        IMAP_SERVER: str = Field(
            default="imap.example.com", description="IMAP server address"
        )
        IMAP_PORT: int = Field(
            default=143, description="IMAP server port (143 for STARTTLS, 993 for SSL)"
        )
        USE_SSL: bool = Field(default=False, description="Use SSL/TLS for connection")
        VERIFY_SSL: bool = Field(
            default=True,
            description="Verify SSL certificate (disable for self-signed certs)",
        )
        EMAIL: str = Field(
            default="user@example.com", description="Email address for authentication"
        )
        PASSWORD: str = Field(
            default="password", description="App password for authentication"
        )

        INCLUDE_METADATA: bool = Field(
            default=True,
            description="Include email metadata (subject, sender, date) in context",
        )
        MAX_EMAILS_TO_SCAN: int = Field(
            default=10,
            ge=1,
            le=1000,
            description="Maximum number of emails to process (1-1000)",
        )
        FOLDER: str = Field(default="INBOX", description="IMAP folder to search")
        SEARCH_CRITERIA: str = Field(
            default="ALL",
            description="IMAP search criteria (e.g., 'UNSEEN', 'SUBJECT \"important\"')",
        )

    def __init__(self):
        self.valves = self.Valves()
        # self.citation = False  # Disable auto-citations

    async def get_email_context(
        self,
        imap_folder: str,
        query: str,
        __event_emitter__: Callable[[dict], Any] = None,
    ) -> str:
        """
        Retrieves emails from open_webui.configured IMAP account and returns them as context.
        Processes emails from newest to oldest when sorting is enabled.

        param imap_folder: Optional imap folder name for fetching emails.
        param query: Optional imap Query for searching mails. If not specified, use "ALL"
        :return: The content of the mails including meta information
        """
        emitter = EventEmitter(__event_emitter__)

        if (imap_folder is None) or (not imap_folder):
            imap_folder = self.valves.FOLDER

        try:
            await emitter.progress_update("Connecting to email server...")

            # Validate port/SSL combination
            if self.valves.USE_SSL and self.valves.IMAP_PORT != 993:
                await emitter.progress_update(
                    "Warning: Using SSL with non-standard port 993"
                )

            # Establish connection
            if self.valves.USE_SSL:
                client = imaplib.IMAP4_SSL(
                    self.valves.IMAP_SERVER,
                    self.valves.IMAP_PORT,
                    ssl_context=(
                        None
                        if self.valves.VERIFY_SSL
                        else imaplib.ssl._create_unverified_context()
                    ),
                )
            else:
                client = imaplib.IMAP4(self.valves.IMAP_SERVER, self.valves.IMAP_PORT)
                try:
                    await emitter.progress_update("Starting TLS encryption...")
                    ssl_context = imaplib.ssl.SSLContext(
                        imaplib.ssl.PROTOCOL_TLS_CLIENT
                    )
                    if not self.valves.VERIFY_SSL:
                        ssl_context.check_hostname = False
                        ssl_context.verify_mode = imaplib.ssl.CERT_NONE
                    client.starttls(ssl_context=ssl_context)
                except Exception as e:
                    await emitter.error_update(f"STARTTLS failed: {str(e)}")
                    return f"Error: STARTTLS failed - {str(e)}"

            # Authenticate
            await emitter.progress_update("Authenticating...")
            try:
                client.login(self.valves.EMAIL, self.valves.PASSWORD)
            except Exception as e:
                await emitter.error_update(f"Authentication failed: {str(e)}")
                return f"Error: Authentication failed - {str(e)}"

            # Select folder
            await emitter.progress_update(f"Accessing folder...")
            try:
                status, _ = client.select(imap_folder)
                if status != "OK":
                    imap_folder = self.valves.FOLDER
                    status, _ = client.select(imap_folder)
                    if status != "OK":
                        raise Exception(f"Folder selection failed: {status}")

            except Exception as e:
                await emitter.error_update(f"Folder error: {str(e)}")
                return f"Error: Folder access failed - {str(e)}"

            # Search emails
            await emitter.progress_update("Searching emails...")
            try:

                status, data = client.search(None, query)
                if status != "OK":
                    query = self.valves.SEARCH_CRITERIA
                    status, data = client.search(None, query)
                    if status != "OK":
                        raise Exception(f"Search failed: {status}")
                email_ids = [eid.decode() for eid in data[0].split()]

                # First reverse the order of email_ids
                reversed_email_ids = email_ids[::-1]

                # Apply max emails limit (take the first MAX_EMAILS_TO_SCAN)
                max_emails = self.valves.MAX_EMAILS_TO_SCAN
                email_ids = reversed_email_ids[:max_emails]

                if not email_ids:
                    await emitter.success_update("No emails found")
                    return "No relevant emails found"

                total = len(email_ids)
                logging.info("emails: " + str(total))

            except Exception as e:
                await emitter.error_update(f"Search error: {str(e)}")
                return f"Error: Search failed - {str(e)}"

            # Process emails
            emails = []

            for idx, e_id in enumerate(email_ids):
                await emitter.progress_update(f"Processing email {idx+1}/{total}...")
                try:
                    status, msg_data = client.fetch(e_id, "(RFC822)")
                    if status != "OK":
                        raise Exception(f"Fetch failed: {status}")

                    # Convert to string immediately to avoid passing Message objects
                    if not msg_data or not isinstance(msg_data[0], tuple):
                        logging.error(f"Invalid data for UID {e_id}")
                        continue

                    raw_email_part = msg_data[0][1]
                    if raw_email_part is None:  # ← Critical check
                        logging.error(f"Missing email body for ID {e_id}")
                        continue

                    raw_email = raw_email_part.decode("utf-8", errors="replace")
                    email_content = await self._parse_email(
                        raw_email, __event_emitter__
                    )
                    if email_content is None:
                        logging.error(f"Missing email body for ID {e_id}")
                        continue

                    emails.append(email_content)
                    # always the same email? -> no!
                    # await emitter.progress_update(f"{email_content}")

                except Exception as e:
                    await emitter.error_update(f"Failed to process email: {str(e)}")
                    continue

            client.logout()
            await emitter.success_update(
                f"Processed {len(emails)} emails from folder {imap_folder} with query {query}"
            )
            retmails = "\n\n".join(emails)
            # await emitter.success_update(f"{retmails}")
            return retmails

        except Exception as e:
            await emitter.error_update(f"Unexpected error: {str(e)}")
            return f"Error: {str(e)}"

    async def _parse_email(self, raw_email: str, __event_emitter__=None) -> str:
        """Parse raw email string instead of Message object"""
        msg = email.message_from_string(raw_email, policy=default)
        sfrom = "unknown"
        ssubject = "unknown"
        metadata = ""
        if self.valves.INCLUDE_METADATA:
            sfrom = msg.get("From", "Unknown")
            ssubject = msg.get("Subject", "No Subject")
            metadata = (
                f"From: {sfrom}\n"
                f"To: {msg.get('To', 'Unknown')}\n"
                f"Date: {msg.get('Date', 'Unknown')}\n"
                f"Subject: {ssubject}\n"
            )
            logging.info(metadata)

        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == "text/plain":
                    charset = part.get_content_charset() or "utf-8"

                    try:
                        payload = part.get_payload(decode=True)
                        if not payload:
                            continue
                        body = payload.decode(charset, errors="replace")
                    except LookupError:  # ← Handle invalid charset
                        body = part.get_payload(decode=True).decode(
                            "utf-8", errors="replace"
                        )
                else:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        payload = part.get_payload(decode=True)
                        if not payload:
                            continue
                        body = payload.decode(charset, errors="replace")
                    except LookupError:  # ← Handle invalid charset
                        body = part.get_payload(decode=True).decode(
                            "utf-8", errors="replace"
                        )

                    body = self._strip_html_tags(str(body))
                    if not body:
                        body = "[No text content found in email]"

        await __event_emitter__(
            {
                "type": "citation",
                "data": {
                    "document": [body],
                    "metadata": [
                        {
                            "date_accessed": datetime.now().isoformat(),
                            "source": ssubject,
                        }
                    ],
                    "source": {"name": sfrom, "url": ""},
                },
            }
        )

        return f"{metadata}Body:\n{str(body)}(End of Mail)\n\n"

    def _strip_html_tags(self, html: str) -> str:
        """Remove HTML tags (including inline CSS in <style> tags and attributes) and clean up whitespace"""
        try:
            # Remove content within <style> and <script> tags (case-insensitive)
            text = re.sub(
                r"<(style|script)\b[^>]*>.*?</\1>",
                "",
                html,
                flags=re.DOTALL | re.IGNORECASE,
            )
            # Remove all HTML tags (including those with inline CSS like style="...")
            text = re.sub(r"<[^>]+>", "  ", text)
            # Replace common HTML entities
            text = re.sub(
                r"&nbsp;|&amp;|&lt;|&gt;",
                lambda match: {
                    "&nbsp;": "  ",
                    "&amp;": "&",
                    "&lt;": "<",
                    "&gt;": ">",
                }[match.group(0).lower()],
                text,
                flags=re.IGNORECASE,
            )
            # Normalize whitespace
            text = re.sub(r"\s+", " ", text).strip()
            return text
        except Exception as e:
            print(f"Error stripping HTML/CSS: {e}")
            return html  # Fallback to original input

    def _clean_whitespace(self, text: str) -> str:
        """Clean up excessive whitespace"""
        text = re.sub(r"\s+", " ", text)  # Replace multiple whitespace
        text = re.sub(r"\n{3,}", "\n\n", text)  # Limit line breaks
        return text.strip()


class ImapEmailProviderTest(unittest.IsolatedAsyncioTestCase):
    async def test_invalid_credentials(self):
        tools = Tools()
        tools.valves = Tools.Valves(
            IMAP_SERVER="imap.example.com",
            EMAIL="invalid@example.com",
            PASSWORD="wrongpassword",
        )
        response = await tools.get_email_context()
        self.assertTrue("Authentication failed" in response)


if __name__ == "__main__":
    print("Running tests...")
    unittest.main()
