"""Генерация recovery kit (PDF + текстовый файл).

Используется:
  * при первичной настройке (setup): содержит креды superuser'а,
    инструкцию для SUPERVISOR, recovery codes;
  * при ротации break-glass-пароля: обновляет PDF.

Требует reportlab или weasyprint. Если нет — fallback на plain text.
"""
from __future__ import annotations

import secrets
import string
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from pathlib import Path

from django.conf import settings
from loguru import logger


def generate_password(length: int = 24) -> str:
    """Случайный пароль с символами."""

    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_recovery_codes(count: int = 10, length: int = 12) -> list[str]:
    """Резервные коды для MFA."""
    
    alphabet = string.ascii_uppercase + string.digits
    return [
        "-".join(
            "".join(secrets.choice(alphabet) for _ in range(4))
            for _ in range(3)
        )
        for _ in range(count)
    ]


@dataclass
class RecoveryKitData:
    username: str
    password: str
    full_name: str = ""
    email: str = ""
    recovery_codes: list[str] = None
    notes: str = ""
    generated_at: datetime = None

    def __post_init__(self):
        if self.recovery_codes is None:
            self.recovery_codes = []
        if self.generated_at is None:
            self.generated_at = datetime.now()


def _render_text(data: RecoveryKitData) -> str:
    lines = [
        "=" * 72,
        "  POSTINSTALL-SERVER — RECOVERY KIT",
        "=" * 72,
        "",
        f"Сгенерировано: {data.generated_at:%Y-%m-%d %H:%M:%S}",
        "",
        "ВАЖНО: этот файл содержит критичные секреты.",
        "Сохраните его в защищённом месте. После первого входа",
        "смените пароль и удалите файл.",
        "",
        "-" * 72,
        "УЧЁТНАЯ ЗАПИСЬ",
        "-" * 72,
        f"Логин:  {data.username}",
        f"Пароль: {data.password}",
    ]
    if data.full_name:
        lines.append(f"ФИО:    {data.full_name}")
    if data.email:
        lines.append(f"Email:  {data.email}")

    if data.recovery_codes:
        lines += [
            "",
            "-" * 72,
            "РЕЗЕРВНЫЕ КОДЫ (использовать при потере MFA)",
            "-" * 72,
        ]
        for i, code in enumerate(data.recovery_codes, 1):
            lines.append(f"  {i:>2}. {code}")
        lines.append("")
        lines.append("Каждый код одноразовый. Сохраните их отдельно от пароля.")

    if data.notes:
        lines += [
            "",
            "-" * 72,
            "ИНСТРУКЦИЯ",
            "-" * 72,
            data.notes,
        ]

    lines += [
        "",
        "=" * 72,
        "  КОНЕЦ",
        "=" * 72,
    ]
    return "\n".join(lines)


def _render_pdf(data: RecoveryKitData) -> bytes | None:
    """Попытка отрисовать PDF через reportlab. None, если не установлен."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
        )
    except ImportError:
        return None

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4,
                             leftMargin=20 * mm, rightMargin=20 * mm,
                             topMargin=20 * mm, bottomMargin=20 * mm)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "Title", parent=styles["Heading1"], alignment=1,
    )
    mono = ParagraphStyle("Mono", parent=styles["Code"],
                          fontSize=11, leading=14)
    body = styles["BodyText"]

    story = [
        Paragraph("POSTINSTALL-SERVER — RECOVERY KIT", title_style),
        Spacer(1, 10 * mm),
        Paragraph(
            f"Сгенерировано: {data.generated_at:%Y-%m-%d %H:%M:%S}",
            body,
        ),
        Spacer(1, 5 * mm),
        Paragraph(
            "<b>ВАЖНО:</b> этот файл содержит критичные секреты. "
            "Сохраните его в защищённом месте.",
            body,
        ),
        Spacer(1, 10 * mm),
        Paragraph("<b>УЧЁТНАЯ ЗАПИСЬ</b>", styles["Heading2"]),
        Paragraph(f"Логин: <font face='Courier'>{data.username}</font>", body),
        Paragraph(f"Пароль: <font face='Courier'>{data.password}</font>", mono),
    ]
    if data.full_name:
        story.append(Paragraph(f"ФИО: {data.full_name}", body))
    if data.email:
        story.append(Paragraph(f"Email: {data.email}", body))

    if data.recovery_codes:
        story += [
            Spacer(1, 10 * mm),
            Paragraph("<b>РЕЗЕРВНЫЕ КОДЫ</b>", styles["Heading2"]),
            Paragraph("Каждый код одноразовый.", body),
        ]
        for i, code in enumerate(data.recovery_codes, 1):
            story.append(Paragraph(f"{i:>2}. {code}", mono))

    if data.notes:
        story += [
            Spacer(1, 10 * mm),
            Paragraph("<b>ИНСТРУКЦИЯ</b>", styles["Heading2"]),
            Paragraph(data.notes.replace("\n", "<br/>"), body),
        ]

    doc.build(story)
    return buf.getvalue()


def write_recovery_kit(data: RecoveryKitData, out_dir: Path) -> tuple[Path, Path | None]:
    """Записать recovery kit в файлы.

    Возвращает (txt_path, pdf_path_or_none).
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        out_dir.chmod(0o700)
    except OSError:
        pass

    ts = data.generated_at.strftime("%Y%m%d-%H%M%S")
    base = out_dir / f"recovery-kit-{data.username}-{ts}"

    txt_path = base.with_suffix(".txt")
    txt_path.write_text(_render_text(data), encoding="utf-8")
    try:
        txt_path.chmod(0o600)
    except OSError:
        pass

    pdf_path = None
    pdf_bytes = _render_pdf(data)
    if pdf_bytes:
        pdf_path = base.with_suffix(".pdf")
        pdf_path.write_bytes(pdf_bytes)
        try:
            pdf_path.chmod(0o600)
        except OSError:
            pass

    logger.info(f"recovery_kit: written {txt_path}"
                + (f" and {pdf_path}" if pdf_path else ""))
    return txt_path, pdf_path