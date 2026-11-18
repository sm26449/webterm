"""The identity watermark setting: its defaults and `load_watermark` (known keys over the defaults),
read by /api/state and Settings (api.py) and by the public share / replay surfaces
(`share_api.py`). Moved out of api.py.
"""
import json

from . import db


# --- Watermark (overlay de identitate pentru trasabilitatea scurgerilor) -----
# Overlay client-side (tiled canvas) peste workspace-ul autentificat și peste
# link-urile read-only partajate. NU se poate „arde" în transcript (.cast e text
# de terminal), deci rămâne strat de prezentare. Config-ul e un singur JSON în KV.
WATERMARK_DEFAULT = {"enabled": False, "content": "${email} · ${time}",
                     "opacity": 0.08, "angle": -30, "fontSize": 13}


async def load_watermark() -> dict:
    raw = await db.get_setting("watermark")
    if not raw:
        return dict(WATERMARK_DEFAULT)
    try:
        cfg = json.loads(raw)
    except (ValueError, TypeError):
        return dict(WATERMARK_DEFAULT)
    # doar cheile cunoscute, peste default (schema-safe la upgrade/downgrade)
    return {**WATERMARK_DEFAULT, **{k: cfg[k] for k in WATERMARK_DEFAULT if k in cfg}}
