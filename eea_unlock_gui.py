#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EEA Unlock - ממשק גרפי
======================
כל הלוגיקה בקובץ אחד: מוסיף את אזור המחשב לכללי ה-EEA בקובץ
C:\\Windows\\System32\\IntegratedServicesRegionPolicySet.json
עם בחירת כללים אחד-אחד, גיבוי ושחזור בכל רגע.

דרישות: Windows, Python 3.9+, PyQt6  (pip install PyQt6)
הרצה:   python eea_unlock_gui.py   (מבקש הרשאות מנהל בעצמו)

תואם לפורמט הגיבוי/מצב של הסקריפט EEA-Unlock.ps1 (אותה תיקייה ב-ProgramData).
"""
import copy
import ctypes
import datetime
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import traceback
from dataclasses import dataclass, field

APP_TITLE = "EEA Unlock"
LOG_NAME = "eea_unlock.log"
LOG_MAX_BYTES = 1_000_000


def _log_candidates():
    paths = []
    pd = os.environ.get("ProgramData")
    if pd:
        paths.append(os.path.join(pd, "EEAUnlock", LOG_NAME))
    paths.append(os.path.join(tempfile.gettempdir(), LOG_NAME))
    return paths


def log_path():
    """נתיב היומן הקבוע (ProgramData, ואם אי אפשר אז תיקיית TEMP)."""
    for p in _log_candidates():
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "a", encoding="utf-8"):
                pass
            return p
        except Exception:
            continue
    return _log_candidates()[-1]


def write_log(level, msg, details=""):
    """כותב ליומן הקבוע. לא זורק חריגות לעולם, ומסובב את הקובץ כשהוא גדול מ-1MB."""
    try:
        p = log_path()
        try:
            if os.path.getsize(p) > LOG_MAX_BYTES:
                os.replace(p, p + ".1")
        except OSError:
            pass
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        lines = [f"{ts} [{level}] {msg}"]
        if details:
            lines += ["    " + ln for ln in str(details).rstrip().splitlines()]
        with open(p, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception:
        pass


def describe_file(path):
    try:
        st = os.stat(path)
        text = f"{path}: {st.st_size} bytes"
        attrs = getattr(st, "st_file_attributes", None)
        if attrs is not None:
            text += f", attributes=0x{attrs:x}" + (" (read-only)" if attrs & 1 else "")
        return text
    except OSError as exc:
        return f"{path}: {exc}"


def format_exc_full(exc):
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def fatal(msg, details=""):
    """מדווח על שגיאה גם כשאין קונסול (pythonw): יומן קבוע + חלון הודעה של Windows."""
    write_log("ERROR", msg, details)
    full = f"{msg}\n\nפירוט נשמר ב:\n{log_path()}"
    if sys.platform == "win32":
        try:
            ctypes.windll.user32.MessageBoxW(0, full, APP_TITLE, 0x10)
            return
        except Exception:
            pass
    print(full, file=sys.stderr)


def _excepthook(exc_type, exc, tb):
    fatal(f"אירעה שגיאה לא צפויה: {exc}", "".join(traceback.format_exception(exc_type, exc, tb)))


sys.excepthook = _excepthook  # ב-PyQt6 חריגה לא מטופלת בתוך slot אחרת סוגרת את התוכנה בשקט

try:
    from PyQt6.QtCore import Qt, pyqtSignal
    from PyQt6.QtGui import QBrush, QColor, QFont, QTextOption
    from PyQt6.QtWidgets import (
        QAbstractItemView, QApplication, QCheckBox, QComboBox, QFrame, QHBoxLayout,
        QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox, QPlainTextEdit,
        QPushButton, QRadioButton, QScrollArea, QStackedWidget, QTabWidget, QTextBrowser,
        QVBoxLayout, QWidget,
    )
except ImportError as _exc:
    fatal("הספרייה PyQt6 לא נמצאה באותו Python שמריץ את התוכנה.\n"
          "התקינו אותה עם:  pip install PyQt6\n"
          "(אם ההרצה היא כמנהל דרך חשבון אחר, יש להתקין גם עבורו)", str(_exc))
    sys.exit(1)

# ----------------------------------------------------------------------------
# קבועים
# ----------------------------------------------------------------------------
EEA = {
    "AT", "BE", "BG", "CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GF", "GP",
    "GR", "HR", "HU", "IE", "IS", "IT", "LI", "LT", "LU", "LV", "MT", "MQ", "NL", "NO",
    "PL", "PT", "RE", "RO", "SE", "SI", "SK", "YT",
}
LIST_KINDS = ("enabled", "disabled", "enabledFor", "disabledFor")
OTHER_KIND = {"enabled": "disabled", "disabled": "enabled",
              "enabledFor": "disabledFor", "disabledFor": "enabledFor"}
EEA_MIN_HITS = 5  # רשימה עם לפחות כמה מדינות EEA נחשבת "רשימת EEA"

BEN, PRV, RST, UNC, NOE, UNK = "benefit", "privacy", "restrict", "unclear", "noeffect", "unknown"
CAT_LABEL = {
    BEN: "יכולת חדשה",
    PRV: "פחות פרסומות ומעקב",
    RST: "תכונה שנכבית",
    UNC: "לא ברור",
    NOE: "אין שינוי",
    UNK: "כלל חדש",
}
CAT_COLOR = {
    BEN: "#15803d", PRV: "#0f766e", RST: "#b91c1c",
    UNC: "#b45309", NOE: "#6b7280", UNK: "#6b7280",
}

# סיווג הכללים לפי GUID: (קטגוריה, כותרת בעברית פשוטה, הסבר, האם מתועד במקורות חיצוניים).
# "מתועד" = נמצא במקורות ברשת; אחרת זו הערכה לפי שם הכלל בלבד.
CATALOG = {
    # ---------------- יכולות חדשות שנפתחות ----------------
    "{1bca278a-5d11-4acf-ad2f-f9ab6d7f93a6}": (BEN, "אפשר להסיר את Edge", "מוסיף אפשרות להסיר את דפדפן Edge כמו כל אפליקציה רגילה, ומונע מ-Windows להציע אותו שוב.", True),
    "{6002ce31-b807-4f82-820c-2b92e716ab76}": (BEN, "אפשר לכבות חיפוש באינטרנט בתיבת החיפוש", "תיבת החיפוש של Windows תחפש רק במחשב, בלי Bing.", True),
    "{8e779eeb-377c-4373-9e80-56e164fdca7e}": (BEN, "בחירת דפדפן או קורא PDF בלחיצה אחת", "כשמגדירים אפליקציית ברירת מחדל, היא מקבלת בבת אחת את כל סוגי הקישורים והקבצים הרלוונטיים, ואפשר להצמיד אותה לשורת המשימות.", True),
    "{f2775604-739c-4cd2-8463-eb040f7e8bf7}": (BEN, "חיפוש דרך חברות אחרות", "אפליקציות של חברות אחרות יכולות להוסיף תוצאות חיפוש לתיבת החיפוש של Windows.", True),
    "{e462341d-48bf-4a7f-9585-5a4e5b90a079}": (BEN, "הצעות בתיבת החיפוש גם מאפליקציות אחרות", "ההצעות שמופיעות כשפותחים את תיבת החיפוש יכולות לבוא גם מאפליקציות שאינן של מיקרוסופט.", False),
    "{7de951fb-a68f-4cb0-b67b-ae6fbdec83ed}": (BEN, "אפליקציות אחרות יכולות לשנות את הדגשת החיפוש", "אפליקציות חיצוניות יכולות להתאים את ההדגשה בתיבת החיפוש שבשורת המשימות.", False),
    "{407a6a2a-4c34-4945-bd24-cd194635abae}": (BEN, "חיפושים אחרונים גם מאפליקציות אחרות", "רשימת החיפושים האחרונים יכולה להציג גם ספקי חיפוש חיצוניים.", False),
    "{b162c44a-5d51-4fb4-aadd-6b8bf3ea4648}": (BEN, "הפרדה בין רכיבי מערכת לאפליקציות", "Windows מסמן מה שייך למערכת ומה אפליקציה רגילה, וכך אפשר להסיר יותר אפליקציות מובנות.", True),
    "{16d2b50e-fa7c-4bb1-ab17-01d766530b3b}": (BEN, "פיד חדשות של חברה אחרת בלוח הווידג'טים", "מאפשר להתקין פיד חדשות שאינו של מיקרוסופט ולהציג אותו בלוח הווידג'טים (Win+W).", True),
    "{92ca7dcf-f422-4a4b-892e-7883a3ca8d70}": (BEN, "אפשר לכבות את פיד החדשות של מיקרוסופט", "אפשר להסיר את פיד החדשות והפרסומות של מיקרוסופט מלוח הווידג'טים.", True),
    "{3d0c862c-bfd8-4350-af2f-4c42884cc3a8}": (BEN, "קישורים מהווידג'טים נפתחים בדפדפן שלך", "במקום להיפתח תמיד ב-Edge, הם נפתחים בדפדפן ברירת המחדל שבחרת.", True),
    "{608ba944-62eb-4912-a873-127c8a68b98c}": (BEN, "ווידג'טים במסך הנעילה", "מאפשר להציג ווידג'טים גם כשהמסך נעול.", False),
    "{c74bb959-f763-4b9b-9b14-6b312df2c937}": (BEN, "אפשר להסיר את אפליקציית התוכן של תפריט התחל", "אפליקציית רקע של מיקרוסופט שמציגה תוכן בתפריט התחל תהיה ניתנת להסרה.", False),
    "{dbfadcb8-0302-4de0-87be-4dfbb71950f9}": (BEN, "מסכי פרטיות הוגנים יותר", "בהגדרות הפרטיות האפשרויות מוצגות בצורה שווה, בלי להטות אותך לבחור באחת מהן.", False),
    "{9a453b66-5ea7-4322-9aba-b054e914cc67}": (BEN, "אפשר להסיר את Microsoft Store", "אפשר להסיר את החנות. אפליקציות שהותקנו ממנה ימשיכו להתעדכן.", True),
    "{b30e775c-9f50-4f5c-8a3e-ab8c78d439e0}": (BEN, "תפריט השיתוף פתוח לכל האפליקציות", "אפליקציות של חברות אחרות יכולות להופיע כיעד שיתוף בדיוק כמו של מיקרוסופט.", False),
    "{0d8903d8-84f5-4048-af3f-547476d83c3c}": (BEN, "עדכון מהיר לאפליקציות של חברות אחרות", "אפליקציות חיצוניות יכולות להתעדכן דרך מנגנון העדכונים של Windows.", False),
    "{a9aacd21-327a-4747-adc1-9d8f1d0f6704}": (BEN, "חיבור שירותי צ'אט אחרים ל-Copilot", "מאפשר לשירותי צ'אט של חברות אחרות להתחבר לעוזר של Windows.", False),
    # ---------------- פחות פרסומות ומעקב ----------------
    "{1ee2eff2-27f6-4103-b593-6e7d656a54df}": (PRV, "פחות המלצות לאתרים בתפריט התחל", "תפריט התחל לא יציע אתרים מהרשת.", False),
    "{b5113273-5a79-4488-a7b4-0a4fc5d5b194}": (PRV, "פחות מסכי קידום בהגדרה ראשונית", "אחרי התקנה או עדכון גדול יוצגו פחות מסכים שמקדמים שירותים של מיקרוסופט.", False),
    "{75b09d11-2e0d-4029-bd88-b91ec9a229bb}": (PRV, "פחות דפי קידום בתהליכי הגדרה", "בתוך אשפי ההגדרה יופיעו פחות עמודי פרסום.", False),
    "{874ed11b-2ab7-4f1e-b275-6032092e3dda}": (PRV, "אפליקציות מיקרוסופט לא יזהו את פרופיל הדפדפן שלך", "Windows ואפליקציות מיקרוסופט לא ניגשים למזהי הפרופילים בדפדפן.", False),
    "{2bf706de-6dbb-4692-b7ef-84d80c47e927}": (PRV, "פחות דחיפה של Edge", "פחות הודעות ופרסומות שמעודדות לעבור ל-Edge במקום הדפדפן שבחרת.", True),
    "{36996754-e327-483a-902f-523e2ba03239}": (PRV, "פחות פרסום ממוקד", "מיקרוסופט תתאים פחות הודעות קידום לפי הפרופיל שלך.", False),
    "{fc5f578d-597b-47ee-8e0e-051cf79fb2c5}": (PRV, "Copilot לא מוצמד לבד", "עדכון גדול של Windows לא יצמיד את Copilot לשורת המשימות.", True),
    "{e32f3cd4-da4c-4c60-a302-05deb33c5254}": (PRV, "פחות הצעות לגיבוי תיקיות ל-OneDrive", "פחות הודעות שמציעות להעביר את התיקיות שלך ל-OneDrive.", False),
    "{2dd61904-1adf-4a7e-8bce-35a6b913527d}": (PRV, "פחות הצעות לקנות מוצרי מיקרוסופט בהגדרות", "בהגדרות יופיעו פחות הצעות מסחריות (דרך Bing).", False),
    "{dd5d7e7c-3ad7-4e38-b11b-a566f1510d00}": (PRV, "נתוני אבחון מסומנים כמוגבלים", "חלק מנתוני האבחון ש-Windows שולח מסומנים כמוגבלים בשימוש.", False),
    "{cd69e9e4-3778-4418-ba1d-bf0116eeeebe}": (PRV, "פחות שיתוף נתוני ביצועים עם Xbox", "פחות מידע על ביצועי המחשב נשלח למערכת של Xbox.", False),
    # ---------------- תכונות שנכבות ----------------
    "{6033b294-79ff-47eb-bbde-97b4c6479217}": (RST, "הרחבות לקורא המסך Narrator", "תוספות של חברות אחרות לקורא המסך (נגישות) לא יפעלו.", False),
    "{ad2d9176-ef16-42de-ba5e-5f6e5a07abca}": (RST, "חיפוש מיקרוסופט משולב ב-File Explorer", "החיפוש המשולב של מיקרוסופט בתוך סייר הקבצים לא יפעל.", False),
    "{cde299a6-4bb6-4623-ae47-cbf055b70873}": (RST, "מסך מלא של Xbox", "חוויית מסך מלא למשחקים (בעיקר במחשבי כף יד) לא תופעל.", False),
    "{4492387d-5ea5-4e72-9ca0-69067d19502c}": (RST, "אפשרויות גיבוי מוגבלות", "חלק מאפשרויות הגיבוי של Windows יוגבלו.", False),
    "{c053478a-fd9a-4bbf-a794-4ebef4bbf764}": (RST, "קבצי Office אחרונים בהמלצות", "תפריט התחל לא יציג קבצי Office אחרונים בהמלצות.", False),
    "{93f5099b-feeb-42c1-984b-c34851e100aa}": (RST, "ווידג'טים של חברות אחרות בפיד", "עלול להסתיר ווידג'טים של אפליקציות אחרות. אם אתה משתמש בהם, כדאי להשאיר כבוי.", False),
    "{0dcb52b1-6b3f-4e95-8049-bf2281ae2eda}": (RST, "הגבלת שיתוף נתונים של ווידג'טים", "ווידג'טים יקבלו פחות מידע.", False),
    "{4323bb73-d394-4c3a-b9df-224ab359844f}": (RST, "הגבלת שיתוף נתונים של ווידג'טים חיצוניים", "ווידג'טים של חברות אחרות יקבלו פחות מידע, וייתכן שיפעלו פחות טוב.", False),
    "{4ac54d32-0799-405f-9bf4-1fe094cd859c}": (RST, "העוזר Copilot", "Copilot לא יופיע ב-Windows.", True),
    "{1d290cdb-499c-4d42-938a-9b8dceffe998}": (RST, "כניסה אוטומטית לאפליקציות", "Windows לא יכניס אותך אוטומטית ל-Edge, Bing ו-Microsoft Start עם חשבון מיקרוסופט.", True),
    "{37bae007-d2ac-41e8-b1bb-848f04e7858f}": (RST, "התראות ווידג'טים בשורת המשימות", "ווידג'טים לא יציגו התראות בשורת המשימות.", False),
    "{3ffae667-623e-408e-bb30-9f670707c346}": (RST, "חיפושים אחרונים באינטרנט", "תיבת החיפוש לא תציג חיפושים אחרונים מהרשת.", False),
    "{1b4085de-aab1-43f6-9385-c5774b824be9}": (RST, "כניסה לווידג'טים רק עם חשבון ברירת המחדל", "אי אפשר להתחבר לווידג'טים עם חשבון אחר.", False),
    "{0446522c-1359-4a68-9e11-e7e46459b2e7}": (RST, "תגי התראה לווידג'טים חיצוניים", "ווידג'טים של חברות אחרות לא יציגו תגי התראה בשורת המשימות.", False),
    "{263054fb-c39e-41d5-b712-23f340806ca8}": (RST, "ווידג'טים עם תוכן קבוע בלבד", "הווידג'טים יציגו המלצות קבועות, בלי תוכן שמתחלף.", False),
    "{9f39df42-5d54-46fc-aa50-9ae3b1ecd663}": (RST, "שילוב ווידג'טי מיקרוסופט בשורת המשימות", "הווידג'טים של מיקרוסופט יהיו פחות משולבים בשורת המשימות.", False),
    "{f7281e17-d7eb-4224-89d0-8aa12a403410}": (RST, "ווידג'טים כסטטוס במסך הנעילה", "הווידג'טים לא יוצגו כסטטוס במסך הנעילה.", False),
    "{8fae6629-123f-46dd-8c34-042f654b554e}": (RST, "Copilot קורא את הטקסט שעל המסך", "Copilot לא ישתמש בטקסט שעל המסך כדי להבין את ההקשר.", False),
    "{139e6c8f-e543-4dfe-803f-2fdd26b31477}": (RST, "פעולות חכמות של שעון ויומן", "פעולות מבוססות שעון ויומן לא יהיו זמינות.", False),
    "{e2961891-e5ef-436a-b009-7801281c3fbf}": (RST, "OneDrive: המשך מהמקום שבו עצרת", "תכונת ההמשך בין מכשירים תושבת.", False),
    "{9679c1a3-b7b3-4789-87ea-5578f78fe900}": (RST, "Phone Link בתפריט התחל", "הטלפון המקושר לא יוצג בתפריט התחל.", False),
    "{e7a1f3c4-9b2d-4f8a-8c3e-5d7f6a9b1c2e}": (RST, "קבצים מומלצים מהחשבון ב-File Explorer", "קבצים מומלצים מחשבון העבודה או הבית לא יוצגו בדף הבית של סייר הקבצים.", True),
    "{f3a8c2d4-5b7e-4c9a-8f3d-1e2b3c4d5e6f}": (RST, "הצעות פעולה חכמות ב-Explorer ובשולחן העבודה", "הצעות לפעולות אחרי בחירת קובץ או טקסט לא יוצגו.", False),
    "{07fd8bc5-2e71-4290-8cdf-d61d8ecfe184}": (RST, "גיבוי Windows לארגונים", "אפשרות הגיבוי הארגוני לא תהיה זמינה.", False),
    # ---------------- לא ברור ----------------
    "{61bf5046-c5db-4cd3-b6bf-929e5b421a6a}": (UNC, "הדגשות מיקרוסופט בתיבת החיפוש", "ההדגשות של מיקרוסופט בתיבת החיפוש בשורת המשימות יוסתרו. ההשפעה לא ברורה.", False),
    "{5436f3c3-803e-447d-9bd2-b533888df09f}": (UNC, "האם Edge נדרש לחיפוש באינטרנט", "שם הכלל לא חד-משמעי, ולא ברור לאיזה כיוון הוא משפיע.", False),
    "{1f5403a8-5d44-40b9-a002-dda7ce7b0d01}": (UNC, "הסכמה לשיתוף נתוני אבחון", "קשור להסכמה לנתוני אבחון. ההשפעה לא ברורה.", False),
    "{3b6022db-defd-4b4a-b6cf-6004dd657f3c}": (UNC, "הגדרות של פיד החדשות", "קשור להגדרות של פיד החדשות. ההשפעה לא ברורה.", False),
    "{b59b2b22-db72-4e2b-867a-4bfc53290abb}": (UNC, "הצעות מותאמות במקום חוויה מותאמת", "שם הכלל לא חד-משמעי, ולא ברור מה ישתנה.", False),
    "{d935674a-c417-4804-8b01-48d746af7a9e}": (UNC, "רכיב אופציונלי A9", "לא מצאנו הסבר ברור לרכיב הזה.", False),
    "{c8e6c136-c6d1-419c-919a-4f8935662914}": (UNC, "בקשת הסכמה לסנכרון חשבון", "Windows ישאל אותך אם לסנכרן את החשבון עם אפליקציות ומכשירים אחרים. זו הגנה על הפרטיות, אבל גם שאלה נוספת.", True),
    "{b1a7c9e2-3d4f-4a6b-8c9d-1a2b3c4d5e6f}": (UNC, "חיפוש Vega בתיבת החיפוש", "תכונת חיפוש חדשה שלא ברור מה היא עושה.", False),
    "{12c807e4-a5a4-4965-b980-531c108eb39e}": (UNC, "חלון ייצוא נתוני Recall", "קשור לתכונת Recall. ההשפעה לא ברורה.", False),
    "{d3bb16fc-705c-483a-8c4b-4f0e914389c4}": (UNC, "סדר הצגת פעולות מומלצות", "קובע באיזה סדר מוצגות פעולות מומלצות. ההשפעה קטנה.", False),
    "{983e7839-8ee8-4705-81f0-962b8966b7d7}": (UNC, "תיבת חיפוש מעודכנת בשורת המשימות", "הגרסה החדשה של תיבת החיפוש. ההשפעה לא ברורה.", False),
    "{b7f4a1d2-3c8e-4f9a-9b6e-2f1d8a7c4e91}": (UNC, "חשיפת נתוני חיפוש ל-Bing", "שם הכלל לא חד-משמעי, ולא ברור לאיזה כיוון הוא משפיע.", False),
    "{b744cc5a-2ca0-4408-bf38-a565eb58f56e}": (UNC, "שירות איכות ושימוש", "קשור לשירות איסוף נתוני שימוש. ההשפעה לא ברורה.", False),
    "{fab7a223-1bc0-4f83-93d7-a31f0ce31173}": (UNC, "התנהגות מקש Copilot", "קובע מה המקש הייעודי ל-Copilot עושה במקלדות שיש בהן אותו.", False),
    "{f2c18e9d-7b4a-4e32-9c61-3a8d5f0b92c7}": (UNC, "הגנה מפני שינוי ברירות מחדל ברישום", "קשור להגנה על הגדרות ברירת המחדל. ההשפעה לא ברורה.", False),
    # ---------------- אין שינוי בפועל ----------------
    "{63ef7a1e-95a1-4f7b-9d4c-b5ed8e72fe10}": (NOE, "חיפוש ב-File Explorer ניתן להרחבה", "אין שינוי בפועל: ההגדרה זהה בכל המדינות.", False),
    "{13feefcf-0f8a-4df0-b85c-417cbcc68d27}": (NOE, "הדגשת מיקרוסופט בחיפוש", "אין שינוי בפועל: ההגדרה זהה בכל המדינות.", False),
    "{9a9f7273-6d5d-4da8-a8e6-bc3243b84d21}": (NOE, "התאמת הדגשת החיפוש על ידי חברות אחרות", "אין שינוי בפועל: ההגדרה זהה בכל המדינות.", False),
    "{17bcdbb5-6003-4b4a-8da8-db163a9869d5}": (NOE, "הדגשת החיפוש של מיקרוסופט (גרסה 2)", "אין שינוי בפועל: ההגדרה זהה בכל המדינות.", False),
}


# ----------------------------------------------------------------------------
# מודל נתונים
# ----------------------------------------------------------------------------
@dataclass
class Rule:
    key: str
    guid: str
    kind: str
    comment: str
    label: str
    category: str
    default_state: str
    indices: list = field(default_factory=list)
    desc: str = ""
    sure: bool = False

    @property
    def opens(self) -> bool:
        return self.kind.startswith("enabled")


def _guid_norm(value) -> str:
    return str(value).strip().lower() if value else ""


# ----------------------------------------------------------------------------
# זיהוי אזור
# ----------------------------------------------------------------------------
def geoid_to_iso2(geoid: int):
    try:
        buf = ctypes.create_unicode_buffer(8)
        n = ctypes.windll.kernel32.GetGeoInfoW(int(geoid), 4, buf, 8, 0)  # GEO_ISO2 = 4
        if n:
            return buf.value.upper()
    except Exception:
        pass
    return None


def detect_regions():
    """[(code, source)] - Windows בודק לפי DeviceRegion, ולא בהכרח לפי אזור המשתמש."""
    found = []
    if sys.platform != "win32":
        return found
    try:
        import winreg
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Control Panel\DeviceRegion",
                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
            ) as k:
                geo, _ = winreg.QueryValueEx(k, "DeviceRegion")
                iso = geoid_to_iso2(geo)
                if iso:
                    found.append((iso, f"DeviceRegion (HKLM), GeoId={geo}"))
        except OSError:
            pass
        for root, label in ((winreg.HKEY_USERS, r"HKU\.DEFAULT"), (winreg.HKEY_CURRENT_USER, "המשתמש הנוכחי")):
            sub = (r".DEFAULT\Control Panel\International\Geo" if root == winreg.HKEY_USERS
                   else r"Control Panel\International\Geo")
            try:
                with winreg.OpenKey(root, sub) as k:
                    name, _ = winreg.QueryValueEx(k, "Name")
                    if isinstance(name, str) and len(name) == 2 and name.isalpha():
                        found.append((name.upper(), f"{label} Geo"))
            except OSError:
                pass
    except Exception:
        pass
    return found


# ----------------------------------------------------------------------------
# מנוע: קריאה, סריקה, החלה, שחזור
# ----------------------------------------------------------------------------
class Engine:
    def __init__(self):
        sysroot = os.environ.get("SystemRoot", r"C:\Windows")
        progdata = os.environ.get("ProgramData", r"C:\ProgramData")
        self.policy = os.path.join(sysroot, "System32", "IntegratedServicesRegionPolicySet.json")
        self.dir = os.path.join(progdata, "EEAUnlock")
        self.backup = os.path.join(self.dir, "IntegratedServicesRegionPolicySet.json.orig")
        self.state_file = os.path.join(self.dir, "state.json")
        self.restore_cmd = os.path.join(self.dir, "Restore.cmd")
        self.history = []  # יומן משותף למסך הפשוט ולמתקדם

    # ----- מצבים מוכנים -----
    @staticmethod
    def mode_keys(info, mode):
        rules = info["rules"]
        if mode == "full":
            return set(rules)
        return {k for k, r in rules.items() if r.category in (BEN, PRV)}

    @staticmethod
    def classify_mode(info, keys):
        keys = set(keys)
        rules = info["rules"]
        if keys == set(rules):
            return "full"
        if keys == {k for k, r in rules.items() if r.category in (BEN, PRV)}:
            return "recommended"
        return "custom"

    def clear_state(self):
        for path in (self.state_file, self.restore_cmd):
            try:
                os.remove(path)
            except OSError:
                pass

    # ----- עזרים -----
    @staticmethod
    def sha(path):
        if not os.path.exists(path):
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            h.update(f.read())
        return h.hexdigest().upper()

    @staticmethod
    def decode(data: bytes):
        bom = data.startswith(b"\xef\xbb\xbf")
        return json.loads(data.decode("utf-8-sig")), bom

    @staticmethod
    def encode(obj, bom: bool) -> bytes:
        raw = json.dumps(obj, indent=2, ensure_ascii=False).encode("utf-8")
        return (b"\xef\xbb\xbf" + raw) if bom else raw

    def load_state(self):
        try:
            with open(self.state_file, "r", encoding="utf-8-sig") as f:
                return json.load(f)
        except Exception:
            return None

    def save_state(self, state):
        os.makedirs(self.dir, exist_ok=True)
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)

    @staticmethod
    def _run(args):
        """מריץ פקודת מערכת ומחזיר (קוד יציאה, פלט)."""
        if sys.platform != "win32":
            return 0, ""
        try:
            r = subprocess.run(args, stdin=subprocess.DEVNULL, capture_output=True, creationflags=0x08000000)
            out = ((r.stdout or b"") + (r.stderr or b"")).decode("utf-8", "replace").strip()
            return r.returncode, out
        except Exception as exc:
            return 1, f"{type(exc).__name__}: {exc}"

    def _cmd(self, args):
        rc, out = self._run(args)
        if rc != 0:
            write_log("WARN", f"הפקודה נכשלה (קוד {rc}): {' '.join(args)}", out)
        return rc

    def _unlock(self):
        self._cmd(["takeown.exe", "/f", self.policy])
        self._cmd(["icacls.exe", self.policy, "/grant", "*S-1-5-32-544:(F)"])

    def _lock(self):
        self._cmd(["icacls.exe", self.policy, "/setowner", "NT SERVICE\\TrustedInstaller"])

    def write_policy(self, data: bytes):
        """כתיבה בטוחה: אם הכתיבה נכשלה או התוצאה אינה JSON תקין, חוזרים אוטומטית למצב הקודם."""
        with open(self.policy, "rb") as f:
            pre = f.read()
        self._unlock()
        try:
            with open(self.policy, "wb") as f:
                f.write(data)
            with open(self.policy, "rb") as f:
                json.loads(f.read().decode("utf-8-sig"))
        except Exception as exc:
            note = "הקובץ הוחזר למצב הקודם"
            try:
                with open(self.policy, "wb") as f:
                    f.write(pre)
            except Exception as exc2:
                note = f"השחזור האוטומטי נכשל גם הוא: {exc2}"
            self._lock()
            write_log("ERROR", "כתיבת קובץ המדיניות נכשלה",
                      f"{type(exc).__name__}: {exc}\n{note}\n{describe_file(self.policy)}")
            raise RuntimeError(f"הכתיבה נכשלה ({type(exc).__name__}: {exc}). {note}.")
        self._lock()

    def verify(self, rules, keys, targets):
        """קורא את הקובץ מחדש ומחזיר רשימת כללים שלא נקלטו."""
        with open(self.policy, "rb") as f:
            obj, _ = self.decode(f.read())
        return [rules[k].comment for k in keys if k in rules and not self.is_applied(rules[k], obj, targets)]

    def write_restore_cmd(self):
        text = (
            "@echo off\r\nsetlocal\r\ntitle EEA Unlock - Restore\r\nnet session >nul 2>&1\r\n"
            "if errorlevel 1 (\r\n  powershell -NoProfile -Command \"Start-Process -FilePath '%~f0' -Verb RunAs\"\r\n  exit /b\r\n)\r\n"
            'set "F=%SystemRoot%\\System32\\IntegratedServicesRegionPolicySet.json"\r\n'
            'set "B=%~dp0IntegratedServicesRegionPolicySet.json.orig"\r\n'
            'if not exist "%B%" goto nobackup\r\n'
            'takeown /f "%F%" >nul\r\n'
            'icacls "%F%" /grant "*S-1-5-32-544:(F)" >nul\r\n'
            'copy /y "%B%" "%F%" >nul\r\n'
            "if errorlevel 1 goto failed\r\n"
            'icacls "%F%" /setowner "NT SERVICE\\TrustedInstaller" >nul\r\n'
            'del /q "%~dp0state.json" >nul 2>&1\r\n'
            "echo.\r\necho Restored to the original file. Restart is recommended.\r\npause\r\nexit /b 0\r\n"
            ":nobackup\r\necho.\r\necho Backup not found: %B%\r\n"
            "echo Last resort: run  sfc /scannow  or  DISM /Online /Cleanup-Image /RestoreHealth\r\npause\r\nexit /b 1\r\n"
            ":failed\r\necho.\r\necho Restore FAILED. Try: sfc /scannow\r\npause\r\nexit /b 1\r\n"
        )
        with open(self.restore_cmd, "w", encoding="utf-8", newline="") as f:
            f.write(text)

    # ----- סריקה -----
    @staticmethod
    def scan(obj):
        """אוסף את כל רשימות ה-EEA לפי (guid, kind). כללים כפולים בקובץ מאוחדים לשורה אחת."""
        rules = {}
        for i, p in enumerate(obj.get("policies", [])):
            region = (p.get("conditions") or {}).get("region")
            if not isinstance(region, dict):
                continue
            for kind in LIST_KINDS:
                lst = region.get(kind)
                if not isinstance(lst, list):
                    continue
                if sum(1 for c in lst if c in EEA) < EEA_MIN_HITS:
                    continue
                guid = _guid_norm(p.get("guid"))
                key = f"{guid or '#' + str(i)}|{kind}"
                if key not in rules:
                    cat, label, desc, sure = CATALOG.get(guid, (UNK, None, "", False))
                    comment = p.get("$comment") or p.get("name") or "(ללא שם)"
                    if not desc:
                        desc = "כלל חדש שלא מוכר לכלי. לא ברור מה הוא עושה."
                    rules[key] = Rule(key, guid, kind, comment, label or comment, cat,
                                      str(p.get("defaultState", "?")), desc=desc, sure=sure)
                rules[key].indices.append(i)
        return rules

    def analyze(self):
        info = {"error": None, "rules": {}, "ours": False, "backup_ok": False,
                "state": None, "cur_obj": None, "src_obj": None, "src_bom": False,
                "cur_hash": None}
        if not os.path.exists(self.policy):
            info["error"] = f"הקובץ לא נמצא: {self.policy}"
            return info
        try:
            with open(self.policy, "rb") as f:
                cur_bytes = f.read()
            cur_obj, cur_bom = self.decode(cur_bytes)
        except Exception as exc:
            info["error"] = f"לא ניתן לקרוא את הקובץ כ-JSON: {exc}"
            return info
        cur_hash = hashlib.sha256(cur_bytes).hexdigest().upper()
        state = self.load_state()
        ours = bool(state) and state.get("PatchedHash") == cur_hash
        backup_ok = bool(
            ours and os.path.exists(self.backup) and state.get("BackupHash")
            and self.sha(self.backup) == state.get("BackupHash")
        )
        src_obj, src_bom = cur_obj, cur_bom
        if backup_ok:
            with open(self.backup, "rb") as f:
                src_obj, src_bom = self.decode(f.read())
        info.update(rules=self.scan(src_obj), ours=ours, backup_ok=backup_ok, state=state,
                    cur_obj=cur_obj, src_obj=src_obj, src_bom=src_bom, cur_hash=cur_hash)
        return info

    @staticmethod
    def is_applied(rule: Rule, cur_obj, targets):
        if not targets:
            return False
        for idx in rule.indices:
            try:
                lst = cur_obj["policies"][idx]["conditions"]["region"][rule.kind]
            except (KeyError, IndexError, TypeError):
                return False
            if any(t not in lst for t in targets):
                return False
        return True

    # ----- החלה -----
    def apply(self, info, selected_keys, targets, mode="custom"):
        rules = info["rules"]
        obj = copy.deepcopy(info["src_obj"])
        changes = []
        for key in selected_keys:
            rule = rules.get(key)
            if not rule:
                continue
            for idx in rule.indices:
                region = obj["policies"][idx]["conditions"]["region"]
                lst = region[rule.kind]
                lst.extend(t for t in targets if t not in lst)
                other = region.get(OTHER_KIND[rule.kind])
                if isinstance(other, list):
                    other[:] = [x for x in other if x not in targets]
            changes.append({"Index": rule.indices[0], "Kind": rule.kind, "Rule": rule.comment})

        new_bytes = self.encode(obj, info["src_bom"])
        json.loads(new_bytes.decode("utf-8-sig"))  # אימות לפני כתיבה

        os.makedirs(self.dir, exist_ok=True)
        if not info["ours"]:
            try:
                shutil.copy2(self.policy, self.backup)  # הקובץ הנוכחי הוא מקור נקי
            except Exception as exc:
                write_log("ERROR", "יצירת הגיבוי נכשלה", f"{type(exc).__name__}: {exc}\n{describe_file(self.backup)}")
                raise RuntimeError(f"לא ניתן ליצור גיבוי, ולכן לא בוצע שינוי ({type(exc).__name__}: {exc}).")
        backup_hash = self.sha(self.backup)
        with open(self.policy, "rb") as f:
            pre_bytes = f.read()

        self.write_policy(new_bytes)
        missing = self.verify(rules, selected_keys, targets)
        if missing:
            write_log("ERROR", "אחרי הכתיבה חלק מהכללים לא נקלטו בקובץ",
                      "\n".join(missing[:30]) + f"\n{describe_file(self.policy)}")
            try:
                self.write_policy(pre_bytes)
            except Exception as exc2:
                write_log("ERROR", "החזרת הקובץ אחרי כשל אימות נכשלה", str(exc2))
            raise RuntimeError(f"הקובץ נכתב אבל {len(missing)} כללים לא נקלטו, ולכן הוחזר המצב הקודם.")
        self.write_restore_cmd()
        self.save_state({
            "PatchedHash": self.sha(self.policy),
            "BackupHash": backup_hash,
            "Regions": list(targets),
            "Date": datetime.datetime.now().isoformat(timespec="seconds"),
            "Changes": changes,
            "Selected": sorted(selected_keys),
            "Tool": "gui",
            "Mode": mode,
        })
        return len(changes)

    # ----- שחזור -----
    def restore(self, force=False):
        """מחזיר (status, message). status: ok | not_ours | none."""
        state = self.load_state()
        if not state:
            return "none", "אין מה לשחזר: לא נמצא תיעוד של החלה קודמת."
        if not os.path.exists(self.policy):
            raise RuntimeError(f"הקובץ לא נמצא: {self.policy}")
        ours = state.get("PatchedHash") == self.sha(self.policy)
        if not ours and not force:
            return "not_ours", ("הקובץ הנוכחי אינו תוצר של התוכנה (כנראה Windows החזיר אותו למקור).")
        backup_ok = bool(os.path.exists(self.backup) and state.get("BackupHash")
                         and self.sha(self.backup) == state.get("BackupHash"))
        if ours and backup_ok:
            with open(self.backup, "rb") as f:
                self.write_policy(f.read())
            msg = "הקובץ שוחזר מהגיבוי המקורי."
        else:
            with open(self.policy, "rb") as f:
                obj, bom = self.decode(f.read())
            codes = set(state.get("Regions") or [])
            removed = 0
            for p in obj.get("policies", []):
                region = (p.get("conditions") or {}).get("region")
                if not isinstance(region, dict):
                    continue
                for kind in LIST_KINDS:
                    lst = region.get(kind)
                    if isinstance(lst, list) and sum(1 for c in lst if c in EEA) >= EEA_MIN_HITS \
                            and any(c in codes for c in lst):
                        lst[:] = [c for c in lst if c not in codes]
                        removed += 1
            self.write_policy(self.encode(obj, bom))
            msg = f"בוצע שחזור הפוך: האזורים {', '.join(sorted(codes))} הוסרו מ-{removed} רשימות."
        for path in (self.state_file, self.restore_cmd):
            try:
                os.remove(path)
            except OSError:
                pass
        return "ok", msg


# ----------------------------------------------------------------------------
# הרשאות מנהל
# ----------------------------------------------------------------------------
def is_admin() -> bool:
    if sys.platform != "win32":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(pre_regions, debug=False):
    exe = sys.executable
    if not debug and exe.lower().endswith("python.exe"):
        pyw = exe[:-10] + "pythonw.exe"
        exe = pyw if os.path.exists(pyw) else exe
    args = []
    if not getattr(sys, "frozen", False):
        args.append(f'"{os.path.abspath(sys.argv[0])}"')
    if pre_regions:
        args.append(f'--regions {",".join(pre_regions)}')
    if debug:
        args.append("--debug")
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, " ".join(args), None, 1)
    return rc > 32


# ----------------------------------------------------------------------------
# ממשק גרפי
# ----------------------------------------------------------------------------
STYLE = """
* { font-family: "Segoe UI", "Noto Sans Hebrew", sans-serif; font-size: 13px; color: #1f2937; }
QMainWindow, QWidget#root, QWidget#page, QScrollArea, QScrollArea > QWidget > QWidget { background: #f3f4f6; }
QWidget#sidebar { background: white; border-left: 1px solid #e5e7eb; }
QLabel#appName { font-size: 18px; font-weight: 700; color: #111827; padding: 18px 18px 4px 18px; }
QLabel#appSub { color: #6b7280; padding: 0 18px 14px 18px; font-size: 12px; }
QListWidget#nav { background: white; border: none; outline: 0; }
QListWidget#nav::item { padding: 11px 18px; border-radius: 8px; margin: 2px 10px; }
QListWidget#nav::item:selected { background: #eff6ff; color: #1d4ed8; font-weight: 600; }
QListWidget#nav::item:hover:!selected { background: #f9fafb; }
QLabel#pageTitle { font-size: 22px; font-weight: 700; color: #111827; }
QLabel#muted { color: #6b7280; }
QLabel#small { color: #6b7280; font-size: 12px; }
QFrame#card { background: white; border: 1px solid #e5e7eb; border-radius: 12px; }
QLabel#statusMain { font-size: 17px; font-weight: 700; }
QFrame#choice { background: white; border: 2px solid #e5e7eb; border-radius: 12px; }
QFrame#choice[selected="true"] { border: 2px solid #2563eb; background: #eff6ff; }
QLabel#pill { background: #2563eb; color: white; border-radius: 9px; padding: 1px 9px; font-size: 11px; font-weight: 600; }
QLabel#choiceBody { color: #4b5563; }
QPushButton { background: white; border: 1px solid #d1d5db; border-radius: 7px; padding: 7px 14px; }
QPushButton:hover { background: #f9fafb; }
QPushButton:disabled { color: #9ca3af; background: #f3f4f6; }
QPushButton#primary { background: #2563eb; color: white; border: none; font-weight: 600; padding: 9px 22px; font-size: 14px; }
QPushButton#primary:hover { background: #1d4ed8; }
QPushButton#primary:disabled { background: #bfdbfe; color: white; }
QPushButton#danger { color: #b91c1c; border: 1px solid #fca5a5; }
QPushButton#danger:hover { background: #fef2f2; }
QPushButton#link { border: none; background: transparent; color: #2563eb; padding: 2px 6px; }
QPushButton#link:hover { text-decoration: underline; background: transparent; }
QFrame#featureRow { background: white; border: 1px solid #e5e7eb; border-radius: 9px; }
QFrame#featureRow:hover { border: 1px solid #bfdbfe; }
QLabel#rowTitle { font-weight: 600; font-size: 13.5px; }
QLabel#rowDesc { color: #6b7280; font-size: 12.5px; }
QLabel#badgeSure { color: #166534; background: #dcfce7; border-radius: 8px; padding: 1px 8px; font-size: 11px; }
QLabel#badgeGuess { color: #6b7280; background: #f3f4f6; border-radius: 8px; padding: 1px 8px; font-size: 11px; }
QLabel#appliedTag { color: #1d4ed8; font-size: 11px; font-weight: 600; }
QLabel#groupTitle { font-size: 15px; font-weight: 700; }
QLineEdit, QComboBox { background: white; border: 1px solid #d1d5db; border-radius: 7px; padding: 6px 9px; }
QPlainTextEdit, QTextBrowser { background: white; border: 1px solid #e5e7eb; border-radius: 10px; padding: 6px; }
QTabWidget::pane { border: none; }
QTabBar::tab { padding: 7px 16px; background: transparent; color: #6b7280; }
QTabBar::tab:selected { color: #2563eb; border-bottom: 2px solid #2563eb; font-weight: 600; }
QCheckBox::indicator { width: 18px; height: 18px; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: #cbd5e1; border-radius: 4px; min-height: 36px; }
QScrollBar::handle:vertical:hover { background: #94a3b8; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: transparent; }
QTextBrowser a { color: #2563eb; }
QFrame#errBar { background: #fef2f2; border: 1px solid #fecaca; border-radius: 10px; }
QLabel#errText { color: #991b1b; }
"""

GROUPS = [
    (BEN, "יכולות חדשות שנפתחות",
     "דברים ש-Windows מאפשר באירופה ולא במקומות אחרים. אלה היתרונות העיקריים."),
    (PRV, "פחות פרסומות ומעקב",
     "באירופה מיקרוסופט מציגה פחות קידום ואוספת פחות נתונים. גם אלה יתרונות."),
    (RST, "תכונות שנכבות",
     "דברים שקיימים בדרך כלל ולא באירופה. הסימון שלהם משנה את Windows כך שייראה אירופי, "
     "אבל מפסידים תכונות. כדאי להשאיר כבוי אלא אם רוצים בדיוק את החוויה האירופית."),
    (UNC, "לא ברור מה הם עושים",
     "לא הצלחנו להבין בוודאות מה הכללים האלה משנים. עדיף לא לגעת."),
    (UNK, "כללים חדשים שהכלי לא מכיר",
     "כללים שמיקרוסופט הוסיפה אחרי שהכלי נכתב. עדיף לא לגעת."),
    (NOE, "אין שינוי בפועל",
     "ההגדרה זהה בכל המדינות, ולכן החלה שלהם לא משנה כלום."),
]
MODE_NAMES = {"recommended": "מומלץ", "full": "מלא", "custom": "מותאם אישית"}

STATUS_STYLES = {
    "info":  "background:#e0e7ff; color:#3730a3;",
    "ok":    "background:#dcfce7; color:#166534;",
    "warn":  "background:#fef3c7; color:#92400e;",
    "error": "background:#fee2e2; color:#991b1b;",
}

HELP_HTML = """
<div dir="rtl" style="font-size:13px; line-height:150%;">
<h3>מה הכלי עושה?</h3>
<p>Windows מחליט אילו תכונות להפעיל לפי המדינה של המחשב. באיחוד האירופי חוק ה-DMA מחייב את מיקרוסופט
לפתוח אפשרויות מסוימות (למשל להסיר את Edge) ולהגביל אחרות. הכלי מוסיף את המדינה שלך לרשימות של אירופה
בקובץ הגדרות של Windows, כך שהכללים שבחרת יחולו גם עליך.</p>
<h3>איך מבטלים?</h3>
<p>בלחיצה על "בטל והחזר הכול למצב רגיל" בעמוד הראשי. לפני כל שינוי נשמר גיבוי של הקובץ המקורי.
אם משהו משתבש יש גם קובץ <b>Restore.cmd</b> בתיקיית <b>EEAUnlock</b> שתחת ProgramData, שעובד גם בלי הכלי הזה.
מוצא אחרון: הפקודות <b>sfc /scannow</b> או <b>DISM /Online /Cleanup-Image /RestoreHealth</b>.</p>
<h3>מה זה "מתועד" ו"לפי השם"?</h3>
<p><b>מתועד</b>: נמצא במקורות ברשת (מיקרוסופט ואתרי חדשות טכנולוגיה). <b>לפי השם</b>: מיקרוסופט לא מתעדת את הכלל,
וההסבר הוא הערכה שלנו על פי שמו בלבד, ולכן הוא עלול לטעות.</p>
<h3>דברים שחשוב לדעת</h3>
<ul>
<li>עדכון גדול של Windows עלול להחזיר את הקובץ למצבו המקורי. אז פשוט מפעילים שוב.</li>
<li>שינוי הקובץ לא מבטיח שהתכונה תפעל. חלק מהתכונות תלויות גם בגרסת Windows ובהפעלה הדרגתית של מיקרוסופט.</li>
<li>רוב המקורות מ-2023 עד 2025, ומיקרוסופט משנה את ההתנהגות כל הזמן.</li>
<li>הכלי אינו קשור למיקרוסופט. השימוש באחריותך.</li>
</ul>
<h3>מקורות</h3>
<ul>
<li><a href="https://blogs.windows.com/windows-insider/2025/06/02/updates-to-windows-for-the-digital-markets-act/">Microsoft: Updates to Windows for the Digital Markets Act</a></li>
<li><a href="https://blogs.microsoft.com/eupolicy/2023/11/22/windows-updates-comply-dma-edge/">Microsoft EU Policy Blog: Windows updates to comply with the DMA</a></li>
<li><a href="https://www.thurrott.com/windows/windows-11/299372/microsoft-details-how-it-is-changing-windows-to-comply-with-the-eu-dma">Thurrott: how Microsoft is changing Windows for the DMA</a></li>
<li><a href="https://www.xda-developers.com/changes-microsoft-windows-europe-dma/">XDA Developers: all the changes Microsoft made to Windows in Europe</a></li>
<li><a href="https://pureinfotech.com/configure-dma-settings-eu-windows-11/">Pureinfotech: new DMA settings for EU users</a></li>
<li><a href="https://support.microsoft.com/en-us/windows/ai/ai-features/click-to-do-in-recall-do-more-with-what-s-on-your-screen">Microsoft Support: Click to Do (regional variations)</a></li>
</ul>
</div>
"""


def force_ltr(edit: QPlainTextEdit):
    """טקסט מעורב (עברית + נתיבים/מזהים) קריא יותר בפסקאות LTR."""
    edit.setLayoutDirection(Qt.LayoutDirection.LeftToRight)
    opt = edit.document().defaultTextOption()
    opt.setTextDirection(Qt.LayoutDirection.LeftToRight)
    opt.setAlignment(Qt.AlignmentFlag.AlignLeft)
    edit.document().setDefaultTextOption(opt)


class ChoiceCard(QFrame):
    clicked = pyqtSignal(str)

    def __init__(self, key, title, text, pill=None):
        super().__init__()
        self.key = key
        self.setObjectName("choice")
        self.setProperty("selected", False)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(4)
        top = QHBoxLayout()
        self.radio = QRadioButton(title)
        self.radio.setStyleSheet("font-size: 14px; font-weight: 700;")
        self.radio.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        top.addWidget(self.radio)
        if pill:
            tag = QLabel(pill)
            tag.setObjectName("pill")
            top.addWidget(tag)
        top.addStretch(1)
        lay.addLayout(top)
        body = QLabel(text)
        body.setObjectName("choiceBody")
        body.setWordWrap(True)
        body.setContentsMargins(0, 0, 26, 0)
        body.setMinimumHeight(38)
        lay.addWidget(body)

    def mousePressEvent(self, event):
        self.clicked.emit(self.key)

    def set_selected(self, value: bool):
        self.radio.setChecked(value)
        self.setProperty("selected", value)
        self.style().unpolish(self)
        self.style().polish(self)


class FeatureRow(QFrame):
    toggled = pyqtSignal(str, bool)

    def __init__(self, rule: Rule):
        super().__init__()
        self.rule = rule
        self.setObjectName("featureRow")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(12)
        self.cb = QCheckBox()
        self.cb.toggled.connect(lambda v: self.toggled.emit(rule.key, v))
        lay.addWidget(self.cb, 0, Qt.AlignmentFlag.AlignTop)
        col = QVBoxLayout()
        col.setSpacing(2)
        title = QLabel(rule.label)
        title.setObjectName("rowTitle")
        title.setWordWrap(True)
        desc = QLabel(rule.desc)
        desc.setObjectName("rowDesc")
        desc.setWordWrap(True)
        col.addWidget(title)
        col.addWidget(desc)
        lay.addLayout(col, 1)
        side = QVBoxLayout()
        side.setSpacing(3)
        self.badge = QLabel("מתועד" if rule.sure else "לפי השם")
        self.badge.setObjectName("badgeSure" if rule.sure else "badgeGuess")
        self.badge.setToolTip("נמצא במקורות חיצוניים" if rule.sure
                              else "הערכה לפי שם הכלל. מיקרוסופט לא מתעדת אותו, ולכן ההסבר עלול לטעות.")
        self.applied = QLabel("")
        self.applied.setObjectName("appliedTag")
        side.addWidget(self.badge, 0, Qt.AlignmentFlag.AlignRight)
        side.addWidget(self.applied, 0, Qt.AlignmentFlag.AlignRight)
        side.addStretch(1)
        lay.addLayout(side)
        self.setToolTip(f"שם מקורי: {rule.comment}\n{rule.guid or '(ללא GUID)'}")

    def mousePressEvent(self, event):
        self.cb.toggle()

    def set_checked(self, value: bool):
        self.cb.blockSignals(True)
        self.cb.setChecked(value)
        self.cb.blockSignals(False)

    def set_applied(self, value: bool):
        self.applied.setText("מוחל כרגע" if value else "")


class GroupHeader(QWidget):
    def __init__(self, cat, title, subtitle, on_all, on_none):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(2, 14, 2, 4)
        lay.setSpacing(2)
        top = QHBoxLayout()
        self.title = QLabel(title)
        self.title.setObjectName("groupTitle")
        top.addWidget(self.title)
        top.addStretch(1)
        b1 = QPushButton("סמן הכול")
        b1.setObjectName("link")
        b1.clicked.connect(lambda: on_all(cat))
        b2 = QPushButton("בטל סימון")
        b2.setObjectName("link")
        b2.clicked.connect(lambda: on_none(cat))
        top.addWidget(b1)
        top.addWidget(b2)
        lay.addLayout(top)
        sub = QLabel(subtitle)
        sub.setObjectName("muted")
        sub.setWordWrap(True)
        lay.addWidget(sub)


class MainWindow(QMainWindow):
    PAGE_HOME, PAGE_FEATURES, PAGE_DIAG, PAGE_HELP = range(4)

    def __init__(self, engine: Engine, extra_regions=None):
        super().__init__()
        self.engine = engine
        self.extra = [r.upper() for r in (extra_regions or []) if len(r) == 2 and r.isalpha()]
        self.manual = None
        self.info = None
        self.selected = set()
        self.last_error = None
        self._last_analyze_error = None
        self.rows = {}            # key -> FeatureRow
        self.group_headers = {}   # cat -> (header, [rows])
        self.setWindowTitle(APP_TITLE)
        self.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        self.resize(1040, 720)
        self.setMinimumSize(900, 620)
        self._build()
        self.refresh(initial=True)

    # ------------------------------------------------------------ מבנה
    def _build(self):
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # תפריט צד (מימין ב-RTL)
        side = QWidget()
        side.setObjectName("sidebar")
        side.setFixedWidth(200)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(0, 0, 0, 12)
        sl.setSpacing(0)
        name = QLabel("EEA Unlock")
        name.setObjectName("appName")
        sub = QLabel("יכולות Windows של אירופה")
        sub.setObjectName("appSub")
        sl.addWidget(name)
        sl.addWidget(sub)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        for text in ("ראשי", "כל התכונות", "אבחון ויומן", "עזרה ומקורות"):
            self.nav.addItem(QListWidgetItem(text))
        self.nav.currentRowChanged.connect(self._on_nav)
        sl.addWidget(self.nav, 1)
        outer.addWidget(side)

        self.stack = QStackedWidget()
        outer.addWidget(self.stack, 1)
        self.stack.addWidget(self._build_home())
        self.stack.addWidget(self._build_features())
        self.stack.addWidget(self._build_diag())
        self.stack.addWidget(self._build_help())
        self.nav.setCurrentRow(0)

    def _page(self, title, subtitle=None):
        page = QWidget()
        page.setObjectName("page")
        lay = QVBoxLayout(page)
        lay.setContentsMargins(28, 22, 28, 18)
        lay.setSpacing(12)
        t = QLabel(title)
        t.setObjectName("pageTitle")
        lay.addWidget(t)
        if subtitle:
            s = QLabel(subtitle)
            s.setObjectName("muted")
            s.setWordWrap(True)
            lay.addWidget(s)
        return page, lay

    def _on_nav(self, row):
        self.stack.setCurrentIndex(row)

    # ------------------------------------------------------------ עמוד ראשי
    def _build_home(self):
        page, lay = self._page("ראשי", "מפעיל ב-Windows יכולות שנפתחו רק למשתמשים באירופה.")

        card = QFrame()
        card.setObjectName("card")
        cl = QHBoxLayout(card)
        cl.setContentsMargins(18, 14, 18, 14)
        self.dot = QLabel("●")
        self.dot.setStyleSheet("font-size: 26px; color: #9ca3af;")
        cl.addWidget(self.dot)
        col = QVBoxLayout()
        col.setSpacing(1)
        self.st_main = QLabel()
        self.st_main.setObjectName("statusMain")
        self.st_sub = QLabel()
        self.st_sub.setObjectName("muted")
        self.st_sub.setWordWrap(True)
        col.addWidget(self.st_main)
        col.addWidget(self.st_sub)
        cl.addLayout(col, 1)
        lay.addWidget(card)

        self.err_bar = QFrame()
        self.err_bar.setObjectName("errBar")
        el = QHBoxLayout(self.err_bar)
        el.setContentsMargins(14, 10, 14, 10)
        self.err_text = QLabel()
        self.err_text.setObjectName("errText")
        self.err_text.setWordWrap(True)
        btn_err_log = QPushButton("פתח יומן")
        btn_err_log.setObjectName("link")
        btn_err_log.clicked.connect(self.open_log)
        el.addWidget(self.err_text, 1)
        el.addWidget(btn_err_log)
        self.err_bar.hide()
        lay.addWidget(self.err_bar)

        sec = QLabel("מה להפעיל?")
        sec.setStyleSheet("font-weight: 700; font-size: 14px;")
        lay.addWidget(sec)
        self.cards = {
            "recommended": ChoiceCard(
                "recommended", "מומלץ: יתרונות בלבד",
                "פותח אפשרויות שקיימות רק באירופה (למשל הסרת Edge) ומפחית פרסומות ואיסוף נתונים. "
                "לא מכבה שום תכונה.", pill="מומלץ"),
            "full": ChoiceCard(
                "full", "מלא: בדיוק כמו באירופה",
                "מחיל את כל כללי אירופה, כולל כאלה ש-Windows מכבה שם (למשל Copilot וחלק מהווידג'טים)."),
        }
        for c in self.cards.values():
            c.clicked.connect(self.on_pick)
            lay.addWidget(c)

        self.custom_note = QLabel()
        self.custom_note.setObjectName("card")
        self.custom_note.setStyleSheet("background:#fffbeb; border:1px solid #fde68a; border-radius:10px; "
                                       "padding:10px 14px; color:#92400e;")
        self.custom_note.setWordWrap(True)
        lay.addWidget(self.custom_note)

        link_row = QHBoxLayout()
        btn_custom = QPushButton("בחירה אישית של תכונות")
        btn_custom.setObjectName("link")
        btn_custom.clicked.connect(lambda: self.nav.setCurrentRow(self.PAGE_FEATURES))
        link_row.addWidget(btn_custom)
        link_row.addStretch(1)
        lay.addLayout(link_row)

        self.region_row = QFrame()
        rr = QHBoxLayout(self.region_row)
        rr.setContentsMargins(0, 0, 0, 0)
        rr.addWidget(QLabel("לא זיהינו את המדינה שלך. הקלידו קוד בן שתי אותיות (למשל IL):"))
        self.ed_region = QLineEdit()
        self.ed_region.setMaxLength(2)
        self.ed_region.setFixedWidth(60)
        self.ed_region.textChanged.connect(self.on_region_text)
        rr.addWidget(self.ed_region)
        rr.addStretch(1)
        lay.addWidget(self.region_row)

        lay.addStretch(1)
        self.home_note = QLabel("חלק מהאפשרויות תלויות בגרסת Windows, ויופיעו רק אחרי הפעלה מחדש של המחשב.")
        self.home_note.setObjectName("small")
        self.home_note.setWordWrap(True)
        lay.addWidget(self.home_note)

        bar = QHBoxLayout()
        self.btn_primary = QPushButton("הפעל")
        self.btn_primary.setObjectName("primary")
        self.btn_primary.clicked.connect(self.on_apply)
        self.btn_restore = QPushButton("בטל והחזר הכול למצב רגיל")
        self.btn_restore.setObjectName("danger")
        self.btn_restore.clicked.connect(self.on_restore)
        self.lbl_region = QLabel()
        self.lbl_region.setObjectName("small")
        bar.addWidget(self.btn_primary)
        bar.addWidget(self.btn_restore)
        bar.addStretch(1)
        bar.addWidget(self.lbl_region)
        lay.addLayout(bar)
        return page

    # ------------------------------------------------------------ עמוד תכונות
    def _build_features(self):
        page, lay = self._page(
            "כל התכונות",
            "כאן בוחרים בדיוק מה להחיל. כל שורה מסבירה מה היא משנה בפועל. "
            "\"מתועד\" אומר שמצאנו את זה במקורות ברשת, \"לפי השם\" הוא הערכה בלבד.")

        tools = QHBoxLayout()
        b1 = QPushButton("מומלץ")
        b1.setToolTip("מסמן יכולות חדשות ופחות פרסומות/מעקב")
        b1.clicked.connect(lambda: self.set_selection("recommended"))
        b2 = QPushButton("הכול")
        b2.setToolTip("מסמן את כל הכללים, בדיוק כמו מחשב אירופי")
        b2.clicked.connect(lambda: self.set_selection("full"))
        b3 = QPushButton("בטל הכול")
        b3.clicked.connect(lambda: self.set_selection("none"))
        for b in (b1, b2, b3):
            tools.addWidget(b)
        tools.addSpacing(14)
        self.cb_filter = QComboBox()
        self.cb_filter.addItem("הצג הכול", None)
        for cat, title, _ in GROUPS:
            self.cb_filter.addItem(title, cat)
        self.cb_filter.currentIndexChanged.connect(self.apply_filter)
        tools.addWidget(self.cb_filter)
        self.ed_search = QLineEdit()
        self.ed_search.setPlaceholderText("חיפוש...")
        self.ed_search.textChanged.connect(self.apply_filter)
        tools.addWidget(self.ed_search, 1)
        lay.addLayout(tools)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.rows_host = QWidget()
        self.rows_layout = QVBoxLayout(self.rows_host)
        self.rows_layout.setContentsMargins(0, 0, 8, 0)
        self.rows_layout.setSpacing(6)
        self.scroll.setWidget(self.rows_host)
        lay.addWidget(self.scroll, 1)

        bar = QHBoxLayout()
        self.btn_apply2 = QPushButton("הפעל")
        self.btn_apply2.setObjectName("primary")
        self.btn_apply2.clicked.connect(self.on_apply)
        self.lbl_count = QLabel()
        bar.addWidget(self.btn_apply2)
        bar.addStretch(1)
        bar.addWidget(self.lbl_count)
        lay.addLayout(bar)
        return page

    def _rebuild_rows(self):
        while self.rows_layout.count():
            w = self.rows_layout.takeAt(0).widget()
            if w:
                w.deleteLater()
        self.rows.clear()
        self.group_headers.clear()
        if not self.info or self.info["error"]:
            return
        rules = list(self.info["rules"].values())
        for cat, title, subtitle in GROUPS:
            members = sorted((r for r in rules if r.category == cat), key=lambda r: r.label)
            if not members:
                continue
            header = GroupHeader(cat, f"{title} ({len(members)})", subtitle,
                                 lambda c: self.set_group(c, True), lambda c: self.set_group(c, False))
            self.rows_layout.addWidget(header)
            group_rows = []
            for r in members:
                row = FeatureRow(r)
                row.toggled.connect(self.on_row_toggled)
                self.rows_layout.addWidget(row)
                self.rows[r.key] = row
                group_rows.append(row)
            self.group_headers[cat] = (header, group_rows)
        self.rows_layout.addStretch(1)

    # ------------------------------------------------------------ אבחון ויומן
    def _build_diag(self):
        page, lay = self._page("אבחון ויומן", "כל פעולה ושגיאה נשמרות ביומן קבוע, כדי שאפשר יהיה להבין מה השתבש.")
        row = QHBoxLayout()
        for text, fn in (("פתח את קובץ היומן", self.open_log), ("פתח את תיקיית היומן", self.open_log_folder),
                         ("העתק את היומן ללוח", self.copy_log), ("רענן", self.reload_log)):
            b = QPushButton(text)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)
        self.log_path_label = QLabel(f"קובץ היומן: {log_path()}")
        self.log_path_label.setObjectName("small")
        self.log_path_label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        lay.addWidget(self.log_path_label)
        tabs = QTabWidget()
        self.diag = QPlainTextEdit()
        self.diag.setReadOnly(True)
        force_ltr(self.diag)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        force_ltr(self.log_view)
        tabs.addTab(self.log_view, "יומן")
        tabs.addTab(self.diag, "אבחון")
        lay.addWidget(tabs, 1)
        self.reload_log()
        return page

    # ----- יומן קבוע -----
    def reload_log(self):
        try:
            with open(log_path(), "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()[-400:]
            self.log_view.setPlainText("\n".join(lines) if lines else "(היומן ריק)")
        except Exception as exc:
            self.log_view.setPlainText(f"לא ניתן לקרוא את היומן: {exc}")
        self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())

    def open_log(self):
        path = log_path()
        if sys.platform == "win32":
            try:
                os.startfile(path)  # noqa
                return
            except Exception as exc:
                write_log("WARN", "פתיחת היומן נכשלה", str(exc))
        QMessageBox.information(self, APP_TITLE, f"קובץ היומן נמצא כאן:\n{path}")

    def open_log_folder(self):
        folder = os.path.dirname(log_path())
        if sys.platform == "win32":
            try:
                os.startfile(folder)  # noqa
                return
            except Exception as exc:
                write_log("WARN", "פתיחת תיקיית היומן נכשלה", str(exc))
        QMessageBox.information(self, APP_TITLE, f"תיקיית היומן:\n{folder}")

    def copy_log(self):
        QApplication.clipboard().setText(self.log_view.toPlainText())

    def _build_help(self):
        page, lay = self._page("עזרה ומקורות")
        br = QTextBrowser()
        br.setOpenExternalLinks(True)
        br.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
        br.setHtml(HELP_HTML)
        lay.addWidget(br, 1)
        return page

    # ------------------------------------------------------------ אזורים
    def targets(self):
        codes = [c for c, _ in detect_regions()] + self.extra
        if self.manual:
            codes.append(self.manual)
        return [c for c in dict.fromkeys(codes) if c not in EEA]

    def on_region_text(self, text):
        t = text.strip().upper()
        self.manual = t if (len(t) == 2 and t.isalpha() and t not in EEA) else None
        self.update_view()

    # ------------------------------------------------------------ יומן
    def log(self, msg, level="INFO"):
        write_log(level, msg)
        self.log_view.appendPlainText(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [{level}] {msg}")

    def _context(self):
        info = self.info or {}
        return (f"regions={self.targets()} selected={len(self.selected)} admin={is_admin()} "
                f"ours={info.get('ours')} backup_ok={info.get('backup_ok')}\n"
                f"{describe_file(self.engine.policy)}\n{describe_file(self.engine.backup)}")

    def _show_error_dialog(self, text, exc):
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Critical)
        box.setWindowTitle(APP_TITLE)
        box.setText(text)
        box.setInformativeText(f"הפרטים נשמרו ביומן:\n{log_path()}")
        box.setDetailedText(f"{type(exc).__name__}: {exc}")
        b_open = box.addButton("פתח יומן", QMessageBox.ButtonRole.ActionRole)
        b_copy = box.addButton("העתק פרטים", QMessageBox.ButtonRole.ActionRole)
        box.addButton("סגור", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        clicked = box.clickedButton()
        if clicked is b_open:
            self.open_log()
        elif clicked is b_copy:
            QApplication.clipboard().setText(f"{text}\n{type(exc).__name__}: {exc}\n{self._context()}")

    def report_error(self, op, text, exc):
        """רושם שגיאה ביומן הקבוע (עם הקשר ו-traceback), מציג פס שגיאה ומודיע למשתמש."""
        write_log("ERROR", f"{op}: {text}", f"{type(exc).__name__}: {exc}\n{self._context()}\n{format_exc_full(exc)}")
        self.log_view.appendPlainText(
            f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [ERROR] {op}: {type(exc).__name__}: {exc}")
        self.last_error = f"{op}: {exc}"
        self.err_text.setText(f"הפעולה האחרונה נכשלה: {text} פרטים נשמרו ביומן.")
        self.err_bar.show()
        self._show_error_dialog(text, exc)

    def clear_error(self):
        self.last_error = None
        self.err_bar.hide()

    # ------------------------------------------------------------ רענון
    def refresh(self, initial=False):
        self.info = self.engine.analyze()
        info = self.info
        if info["error"] and info["error"] != self._last_analyze_error:
            write_log("WARN", "קריאת קובץ המדיניות נכשלה", f"{info['error']}\n{describe_file(self.engine.policy)}")
        self._last_analyze_error = info["error"]
        self._rebuild_rows()
        rules = info["rules"]
        if initial:
            state = info.get("state")
            if info["ours"] and state and state.get("Selected") is not None:
                self.selected = set(state["Selected"]) & set(rules)
            else:
                self.selected = self.engine.mode_keys(info, "recommended") if rules else set()
            self.log("הכלי נפתח")
        elif rules:
            self.selected &= set(rules)   # אם הקובץ לא נקרא (שגיאה), שומרים על הבחירה הקיימת
        for key, row in self.rows.items():
            row.set_checked(key in self.selected)
        self.update_view()
        self.update_diag()
        self.apply_filter()

    def applied_selection(self):
        info = self.info
        state = info.get("state")
        if not (info["ours"] and state):
            return None
        if state.get("Selected") is not None:
            return set(state["Selected"])
        tg = state.get("Regions") or []
        return {k for k, r in info["rules"].items() if self.engine.is_applied(r, info["cur_obj"], tg)}

    def update_view(self):
        info = self.info
        tg = self.targets()
        mode = self.engine.classify_mode(info, self.selected) if info["rules"] else "custom"

        for k, c in self.cards.items():
            c.set_selected(k == mode)
        self.custom_note.setVisible(mode == "custom" and not info["error"])
        self.custom_note.setText(f"בחירה אישית: {len(self.selected)} תכונות מסומנות. "
                                 "אפשר לראות ולשנות אותן ב\"כל התכונות\".")
        self.region_row.setVisible(not tg and not info["error"])
        self.lbl_region.setText(f"המדינה שזוהתה: {', '.join(tg)}" if tg else "")

        applied = self.applied_selection()
        state = info.get("state")
        if info["error"]:
            self._status("#dc2626", "אי אפשר להפעיל כאן",
                         "הכלי עובד ב-Windows 10/11 שיש בו קובץ הגדרות אזור. פרטים באבחון.")
        elif applied is not None:
            applied_mode = self.engine.classify_mode(info, applied)
            self._status("#16a34a", "פעיל",
                         f"מצב: {MODE_NAMES[applied_mode]} · {len(applied)} תכונות. אפשר לבטל בכל רגע.")
        elif state:
            self._status("#d97706", "Windows חזר להגדרות המקור",
                         "כנראה בגלל עדכון. לחצו \"הפעל\" כדי להחיל שוב.")
        else:
            self._status("#9ca3af", "כבוי", "Windows במצב הרגיל.")

        if applied is not None:
            label = "עדכן לפי הבחירה"
            enabled = bool(tg) and applied != self.selected
        else:
            label = "הפעל"
            enabled = bool(tg) and bool(self.selected)
        if info["error"]:
            enabled = False
        for b in (self.btn_primary, self.btn_apply2):
            b.setText(label)
            b.setEnabled(enabled)
        self.btn_restore.setVisible(applied is not None)

        for key, row in self.rows.items():
            row.set_applied(bool(applied is not None and key in applied))
        self.update_count()

    def _status(self, color, main, sub):
        self.dot.setStyleSheet(f"font-size: 26px; color: {color};")
        self.st_main.setText(main)
        self.st_sub.setText(sub)

    def update_count(self):
        if not self.info:
            return
        rules = self.info["rules"]
        chosen = self.selected & set(rules)
        risky = sum(1 for k in chosen if rules[k].category in (RST, UNC, UNK))
        txt = f"נבחרו {len(chosen)} מתוך {len(rules)}"
        if risky:
            txt += f" · מתוכם {risky} תכונות שנכבות או לא ברורות"
        self.lbl_count.setText(txt)
        self.lbl_count.setStyleSheet("color:#b45309; font-weight:600;" if risky else "color:#4b5563;")

    def update_diag(self):
        info = self.info
        lines = [f"Windows: {platform.platform()}", f"קובץ מדיניות: {self.engine.policy}", ""]
        det = detect_regions()
        lines.append("אזורים שזוהו:" if det else "אזורים שזוהו: (אין)")
        for code, src in det:
            lines.append(f"  {code}   ({src})")
        if info and not info["error"]:
            lines += ["", f"SHA256 של הקובץ הנוכחי: {info['cur_hash']}",
                      f"כללים בקובץ: {len(info['cur_obj'].get('policies', []))}",
                      f"רשימות EEA (מאוחדות לפי GUID וסוג): {len(info['rules'])}"]
            unk = [r for r in info["rules"].values() if r.category == UNK]
            lines.append(f"כללים שלא סווגו: {len(unk)}")
            for r in unk:
                lines.append(f"  - {r.comment}   {r.guid}")
        elif info and info["error"]:
            lines += ["", info["error"]]
        state = info.get("state") if info else None
        lines.append("")
        if state:
            lines += ["מצב שמור:", f"  תאריך: {state.get('Date')}", f"  אזורים: {state.get('Regions')}",
                      f"  הקובץ הנוכחי תואם להחלה: {'כן' if info['ours'] else 'לא'}",
                      f"  גיבוי תקין: {'כן' if info['backup_ok'] else 'לא'}"]
        else:
            lines.append("מצב שמור: אין")
        lines.append(f"יומן קבוע: {log_path()}")
        lines.append(f"גיבוי: {self.engine.backup}")
        lines.append(f"קובץ שחזור עצמאי: {self.engine.restore_cmd}"
                     + ("" if os.path.exists(self.engine.restore_cmd) else "  (לא קיים)"))
        self.diag.setPlainText("\n".join(lines))

    # ------------------------------------------------------------ בחירה וסינון
    def on_pick(self, mode):
        self.set_selection(mode)

    def set_selection(self, mode):
        rules = self.info["rules"] if self.info else {}
        if mode == "none":
            self.selected = set()
        else:
            self.selected = set(self.engine.mode_keys(self.info, mode)) if rules else set()
        for key, row in self.rows.items():
            row.set_checked(key in self.selected)
        self.update_view()

    def on_row_toggled(self, key, checked):
        (self.selected.add if checked else self.selected.discard)(key)
        self.update_view()

    def set_group(self, cat, value):
        for key, r in self.info["rules"].items():
            if r.category == cat:
                (self.selected.add if value else self.selected.discard)(key)
        for key, row in self.rows.items():
            row.set_checked(key in self.selected)
        self.update_view()

    def apply_filter(self):
        cat = self.cb_filter.currentData()
        text = self.ed_search.text().strip().lower()
        for c, (header, rows) in self.group_headers.items():
            visible = 0
            for row in rows:
                r = row.rule
                hide = (cat and r.category != cat) or \
                       (text and text not in (r.label + " " + r.desc + " " + r.comment).lower())
                row.setVisible(not hide)
                visible += 0 if hide else 1
            header.setVisible(visible > 0)

    # ------------------------------------------------------------ פעולות
    def ask_restart(self, text):
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle(APP_TITLE)
        box.setText(text)
        now = box.addButton("הפעל מחדש עכשיו", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("אחר כך", QMessageBox.ButtonRole.RejectRole)
        box.exec()
        if box.clickedButton() is now:
            if QMessageBox.question(self, APP_TITLE, "שמרתם את העבודה? המחשב יופעל מחדש בעוד 15 שניות.") \
                    == QMessageBox.StandardButton.Yes and sys.platform == "win32":
                subprocess.Popen(["shutdown", "/r", "/t", "15", "/c", "EEA Unlock"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, creationflags=0x08000000)

    def on_apply(self):
        info = self.info
        tg = self.targets()
        keys = set(self.selected) & set(info["rules"])
        if not tg:
            QMessageBox.information(self, APP_TITLE, "לא זוהתה מדינה. הקלידו קוד מדינה בעמוד הראשי.")
            return
        if not keys:
            if info.get("state") and info["ours"]:
                if QMessageBox.question(self, APP_TITLE, "לא נבחרה אף תכונה. לבטל את ההחלה הקיימת?") \
                        == QMessageBox.StandardButton.Yes:
                    self.on_restore(confirm=False)
            else:
                QMessageBox.information(self, APP_TITLE, "לא נבחרה אף תכונה.")
            return
        risky = sum(1 for k in keys if info["rules"][k].category in (RST, UNC, UNK))
        msg = ("הכלי ישנה קובץ הגדרות של Windows.\nנשמר גיבוי, ואפשר לבטל הכול בכל רגע.")
        if risky:
            msg += (f"\n\nשימו לב: {risky} מהתכונות שנבחרו מכבות דברים או שלא ברור מה הן עושות. "
                    "אפשר לראות אותן בעמוד \"כל התכונות\".")
        msg += "\n\nלהמשיך?"
        if QMessageBox.question(self, APP_TITLE, msg) != QMessageBox.StandardButton.Yes:
            return
        mode = self.engine.classify_mode(info, keys)
        try:
            n = self.engine.apply(info, keys, tg, mode=mode)
        except Exception as exc:
            self.report_error("החלה", "לא הצלחנו להפעיל. לא בוצע שום שינוי בקובץ.", exc)
            return
        self.clear_error()
        self.log(f"הוחל מצב {MODE_NAMES[mode]}: {n} תכונות עבור {', '.join(tg)}")
        self.refresh()
        self.ask_restart("בוצע!\nכדי שהשינויים ייכנסו לתוקף צריך להפעיל מחדש את המחשב.")

    def on_restore(self, confirm=True):
        if confirm and QMessageBox.question(self, APP_TITLE, "להחזיר את Windows להגדרות המקור?") \
                != QMessageBox.StandardButton.Yes:
            return
        try:
            status, msg = self.engine.restore(force=False)
            if status == "not_ours":
                self.log("שחזור: הקובץ כבר חזר למקור בעצמו, נוקה המצב השמור", "WARN")
                self.engine.clear_state()
                self.refresh()
                QMessageBox.information(self, APP_TITLE,
                                        "Windows כבר החזיר את ההגדרות המקוריות בעצמו, אין מה לבטל.")
                return
        except Exception as exc:
            self.report_error("שחזור", "לא הצלחנו לבטל.", exc)
            return
        self.clear_error()
        self.log(msg)
        self.refresh()
        self.ask_restart("הכול הוחזר למצב רגיל.\nמומלץ להפעיל מחדש את המחשב.")


# ----------------------------------------------------------------------------
def main():
    debug = "--debug" in sys.argv
    extra = []
    if "--regions" in sys.argv:
        try:
            extra = [r for r in sys.argv[sys.argv.index("--regions") + 1].split(",") if r]
        except IndexError:
            pass

    if not is_admin():
        pre = [c for c, _ in detect_regions()] + extra
        write_log("INFO", "אין הרשאות מנהל, מנסה להפעיל מחדש כמנהל")
        if relaunch_as_admin(list(dict.fromkeys(pre)), debug):
            return 0
        fatal("נדרשות הרשאות מנהל כדי לשנות את קובץ המערכת, וההרמה בוטלה או נכשלה.")
        return 1

    write_log("INFO", f"{APP_TITLE} התחיל",
              f"python={sys.version.split()[0]} platform={platform.platform()} admin={is_admin()} "
              f"user={os.environ.get('USERNAME') or os.environ.get('USER')}")

    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setLayoutDirection(Qt.LayoutDirection.RightToLeft)
    app.setStyleSheet(STYLE)
    win = MainWindow(Engine(), extra)
    win.show()
    return app.exec()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except Exception as exc:
        fatal(f"התוכנה נכשלה בהפעלה: {exc}", traceback.format_exc())
        sys.exit(1)
