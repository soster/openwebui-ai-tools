"""
title: Paperless Document Search
description: A Tool to interact with a running paperless server. Inspired by https://github.com/JLeine/open-webui
author: Stefan Ostermann
git_url: https://github.com/soster/openwebui-ai-tools/paperless.py
version: 0.0.1
license: MIT
"""

import json
import requests
from langchain_core.document_loaders import BaseLoader
from langchain_core.documents import Document
from pydantic import BaseModel, Field
from typing import Callable, Any, Iterator, Optional


class DocumentEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Document):
            return {"page_content": obj.page_content, "metadata": obj.metadata}
        return super().default(obj)


class PaperlessDocumentLoader(BaseLoader):
    """Paperless document loader that retrieves documents based on a general search query."""

    def __init__(
        self,
        query: Optional[str] = "",
        url: Optional[str] = "",
        token: Optional[str] = "",
    ) -> None:
        """Initialize the loader with a search query.
        Args:
            query: The general search query to load documents.
            url: The URL to load documents from (optional).
            token: The authorization token for API access (optional).
        """
        self.url = url if url else "/"
        if len(self.url) > 0 and not self.url.endswith("/"):
            self.url += "/"
        self.url += "api/documents/"
        self.token = token if token else ""
        self.query = query

    def lazy_load(self) -> Iterator[Document]:
        """A lazy loader that requests documents from paperless based on the search query."""
        querystring = {"query": self.query}
        headers = {"Authorization": f"Token {self.token}"}
        response = requests.get(self.url, headers=headers, params=querystring)
        if response.status_code == 200:
            data = response.json()
            for result in data["results"]:
                metadata = {
                    "source": f"{self.url.replace('/api', '')}{result['id']}",
                    **result,
                }
                metadata = {
                    k: v
                    for k, v in metadata.items()
                    if v is not None and not isinstance(v, list)
                }
                yield Document(
                    page_content=result["content"],
                    metadata=metadata,
                )


class EventEmitter:
    def __init__(self, event_emitter: Callable[[dict], Any] = None):
        self.event_emitter = event_emitter

    async def progress_update(self, description):
        await self.emit(description)

    async def error_update(self, description):
        await self.emit(description, "error", True)

    async def success_update(self, description):
        await self.emit(description, "success", True)

    async def emit(self, description="Unknown State", status="in_progress", done=False):
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
        PAPERLESS_URL: str = Field(
            default="https://paperless.yourdomain.com/",
            description="The domain of your paperless service",
        )
        PAPERLESS_TOKEN: str = Field(
            default="",
            description="The token to read docs from paperless",
        )

    def __init__(self):
        self.valves = self.Valves()

    async def get_paperless_documents(
        self,
        query: str,
        __event_emitter__: Callable[[dict], Any] = None,
    ) -> str:
        """
        Search for paperless documents using a general search query and retrieve the content of relevant documents.
        :param query: The general search query to filter documents.
        :return: All documents as a JSON string or an error as a string
        """
        emitter = EventEmitter(__event_emitter__)
        try:
            await emitter.progress_update(f"Searching documents for query: {query}")
            loader = PaperlessDocumentLoader(
                query=query,
                url=self.valves.PAPERLESS_URL,
                token=self.valves.PAPERLESS_TOKEN,
            )
            documents = loader.load()
            if len(documents) == 0:
                error_message = f"Query returned 0 results for query: {query}"
                await emitter.error_update(error_message)
                return error_message
            encoded_documents = json.dumps(
                documents, cls=DocumentEncoder, ensure_ascii=False
            )
            decoded_documents = json.loads(encoded_documents)
            if __event_emitter__:
                for document in decoded_documents:
                    await __event_emitter__(
                        {
                            "type": "citation",
                            "data": {
                                "document": [document["page_content"]],
                                "metadata": [{"source": document["metadata"]["title"]}],
                                "source": {"name": document["metadata"]["source"]},
                            },
                        }
                    )
            await emitter.success_update(
                f"Received {len(decoded_documents)} documents for query: {query}"
            )
            return encoded_documents
        except Exception as e:
            error_message = f"Error: {str(e)}"
            await emitter.error_update(error_message)
            return error_message
