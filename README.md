# openwebui-ai-tools

Some cool [Open WebUI](https://openwebui.com/) tools. Open WebUI is a UI for chatting with locally hosted LLMs.

Tested with Open WebUI 0.5.12

## Mail Scanner

Gives your LLM access to your Mails via IMAP.

Use the Tools valve to configure email, password, server and so on.

Supports STARTTLS and SSL encryption.

Example prompt:

```
Can you search my email’s INBOX folder for mails send by "michael@somewhere.com" and summarize them for me?
```

## Paperless

Integration into the [paperless](https://docs.paperless-ngx.com/) document management system. It enables you to chat with your documents!

Use the Tools valve to configure server and API key.

Example prompt:

```
Use the search term “Rechnung 2024” and summarize all invoices for me.
```
