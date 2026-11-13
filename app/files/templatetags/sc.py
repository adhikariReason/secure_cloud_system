from django import template

register = template.Library()

KINDS = {
    "pdf": "pdf", "png": "img", "jpg": "img", "jpeg": "img",
    "docx": "doc", "txt": "txt", "csv": "sheet", "xlsx": "sheet", "pptx": "slide",
    "zip": "zip", "bin": "bin",
}


@register.filter
def hexbytes(value):
    return bytes(value).hex() if value is not None else ""


@register.filter
def short(value, n=10):
    return str(value)[: int(n)]


@register.filter
def filekind(name):
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return KINDS.get(ext, "bin")


@register.filter
def ext(name):
    return (name.rsplit(".", 1)[-1][:4] if "." in name else "file").upper()
