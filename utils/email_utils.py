def send_mail(
    subject: str,
    body: str | None,
    to: list[str] | str | None = None,          # list o str
    html_body: str | None = None,
    from_email: str | None = None,
    inline_logo_path: str | None = None,
    inline_logo_cid: str = "uplaylogo",
    inline_images: dict[str, str] | None = None,
    cc: list[str] | str | None = None,          # NUEVO
    bcc: list[str] | str | None = None,         # NUEVO
    reply_to: str | None = None,                # NUEVO
    **kwargs
) -> bool:
    """
    Envío SMTP con saneo de credenciales (strip/espacios) y logging de diagnóstico.
    Compatibilidad:
      - acepta to_addrs= o recipients= (alias de to)
      - ahora soporta CC/BCC/Reply-To (sin romper llamadas viejas)
    """
    import os, ssl, smtplib, logging, mimetypes, unicodedata
    from email.message import EmailMessage
    try:
        from flask import current_app
    except Exception:
        current_app = None

    # --- MODO DEBUG LOCAL (solo imprime) ---
    if os.getenv("RENDER") is None:  # si no estamos en Render
        print("\n==================== EMAIL DEBUG UPLAY ====================")
        print(f"🧾 Asunto: {subject}")
        print(f"📤 Para: {to}")
        if html_body:
            print("💬 HTML:\n", html_body)
        elif body:
            print("💬 Texto:\n", body)
        print("===========================================================\n")
        return True

    # Logger seguro
    try:
        logger = current_app.logger  # type: ignore[union-attr]
    except Exception:
        logger = logging.getLogger(__name__)

    # --- Normalización destinatarios principales y alias viejos ---
    recipients = to or kwargs.get("to_addrs") or kwargs.get("recipients") or []
    if isinstance(recipients, str):
        recipients = [recipients]
    to_clean = [str(t).strip() for t in recipients if t and str(t).strip()]

    # CC / BCC (opcionales)
    def _norm_list(val):
        if not val:
            return []
        if isinstance(val, str):
            return [val.strip()] if val.strip() else []
        return [str(x).strip() for x in val if x and str(x).strip()]

    cc_clean  = _norm_list(cc)
    bcc_clean = _norm_list(bcc)

    # --- Cargar y SANEAR env vars (evita 535 por espacios ocultos)
    host = (os.getenv("SMTP_HOST", "") or "").strip()
    port = int((os.getenv("SMTP_PORT", "587") or "587").strip())
    user = (os.getenv("SMTP_USER", "") or "").strip()
    pwd  = (os.getenv("SMTP_PASS", "") or "").strip()

    # eliminar espacios internos (p. ej. App Password con espacios)
    pwd = pwd.replace(" ", "")
    # normalizar unicode
    user = unicodedata.normalize("NFKC", user)
    pwd  = unicodedata.normalize("NFKC", pwd)

    use_tls = (os.getenv("SMTP_TLS", "1") or "1").strip() == "1"
    use_ssl = (os.getenv("SMTP_SSL", "0") or "0").strip() == "1"

    sender_env = (os.getenv("SMTP_FROM") or "").strip()
    sender = from_email or sender_env or (user or "")

    # Validaciones mínimas
    if not host or not port or not sender or not (to_clean or cc_clean or bcc_clean):
        logger.warning(
            "SMTP: faltan variables o destinatarios. host=%r port=%r sender=%r to=%r cc=%r bcc=%r",
            host, port, sender, to_clean, cc_clean, bcc_clean
        )
        return False

    # --- Mensaje
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    if to_clean:
        msg["To"] = ", ".join(to_clean)
    if cc_clean:
        msg["Cc"] = ", ".join(cc_clean)
    if reply_to:
        msg["Reply-To"] = reply_to

    texto_plano = (body or "").strip() or " "
    msg.set_content(texto_plano)

    html_part = None
    if html_body:
        msg.add_alternative(html_body, subtype="html")
        for part in msg.iter_parts():
            try:
                if part.get_content_type() == "text/html":
                    html_part = part
                    break
            except Exception:
                continue

    def _attach_inline(path: str, cid: str):
        nonlocal html_part
        if not (path and html_part):
            return
        try:
            mime_type, _ = mimetypes.guess_type(path)
            maintype, subtype = ("image", "png")
            if mime_type and "/" in mime_type:
                m_maintype, m_subtype = mime_type.split("/", 1)
                if m_maintype == "image" and m_subtype:
                    maintype, subtype = m_maintype, m_subtype
            with open(path, "rb") as f:
                img_bytes = f.read()
            html_part.add_related(img_bytes, maintype=maintype, subtype=subtype, cid=f"<{cid}>")
            logger.info("SMTP: imagen inline embebida cid=%s desde %s (%s/%s)", cid, path, maintype, subtype)
        except Exception as e:
            logger.warning("SMTP: no pude adjuntar inline (%s -> cid=%s): %s", path, cid, e)

    if inline_logo_path and html_part:
        _attach_inline(inline_logo_path, inline_logo_cid)
    if inline_images and html_part:
        for cid, path in inline_images.items():
            if cid and path:
                _attach_inline(path, cid)

    # --- DEBUG
    try:
        logger.info(
            "SMTP debug: host=%r port=%r TLS=%r SSL=%r user=%r from=%r pass_len=%d to=%s cc=%s bcc=%s",
            host, port, use_tls, use_ssl, user, sender, len(pwd or ""), to_clean, cc_clean, bcc_clean
        )
    except Exception:
        pass

    # --- Envío
    try:
        if use_ssl and use_tls:
            logger.warning("SMTP: TLS y SSL habilitados a la vez; desactivando TLS.")
            use_tls = False

        all_rcpts = [*to_clean, *cc_clean, *bcc_clean]

        if use_ssl:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, context=context, timeout=20) as server:
                if user:
                    server.login(user, pwd)
                resp = server.send_message(msg, from_addr=sender, to_addrs=all_rcpts)
        else:
            with smtplib.SMTP(host, port, timeout=20) as server:
                server.ehlo()
                if use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    server.ehlo()
                if user:
                    server.login(user, pwd)
                resp = server.send_message(msg, from_addr=sender, to_addrs=all_rcpts)

        if resp:
            logger.error("SMTP: fallos por destinatario: %s", resp)
            return False

        logger.info("SMTP: envío OK a to=%s cc=%s bcc=%s", to_clean, cc_clean, bcc_clean)
        return True

    except smtplib.SMTPAuthenticationError as e:
        logger.exception("SMTP auth error: %s", e)
        return False
    except smtplib.SMTPConnectError as e:
        logger.exception("SMTP connect error: %s", e)
        return False
    except smtplib.SMTPException as e:
        logger.exception("SMTP error: %s", e)
        return False
    except Exception as e:
        logger.exception("SMTP error inesperado: %s", e)
        return False




def get_or_404(model, pk):
