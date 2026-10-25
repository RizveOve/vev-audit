"""WCAG 2.2 reference data: success criteria, remediation guidance, manual checks."""

from __future__ import annotations

import re

# axe-core tags we run. "best-practice" rules are reported but never mapped to a WCAG criterion.
AXE_RUN_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"]

IMPACT_ORDER = {"critical": 0, "serious": 1, "moderate": 2, "minor": 3}
IMPACTS = tuple(IMPACT_ORDER)

# (number, name, level) — WCAG 2.2. 4.1.1 Parsing is obsolete in 2.2 and omitted.
_CRITERIA = [
    ("1.1.1", "Non-text Content", "A"),
    ("1.2.1", "Audio-only and Video-only (Prerecorded)", "A"),
    ("1.2.2", "Captions (Prerecorded)", "A"),
    ("1.2.3", "Audio Description or Media Alternative (Prerecorded)", "A"),
    ("1.2.4", "Captions (Live)", "AA"),
    ("1.2.5", "Audio Description (Prerecorded)", "AA"),
    ("1.3.1", "Info and Relationships", "A"),
    ("1.3.2", "Meaningful Sequence", "A"),
    ("1.3.3", "Sensory Characteristics", "A"),
    ("1.3.4", "Orientation", "AA"),
    ("1.3.5", "Identify Input Purpose", "AA"),
    ("1.4.1", "Use of Color", "A"),
    ("1.4.2", "Audio Control", "A"),
    ("1.4.3", "Contrast (Minimum)", "AA"),
    ("1.4.4", "Resize Text", "AA"),
    ("1.4.5", "Images of Text", "AA"),
    ("1.4.10", "Reflow", "AA"),
    ("1.4.11", "Non-text Contrast", "AA"),
    ("1.4.12", "Text Spacing", "AA"),
    ("1.4.13", "Content on Hover or Focus", "AA"),
    ("2.1.1", "Keyboard", "A"),
    ("2.1.2", "No Keyboard Trap", "A"),
    ("2.1.4", "Character Key Shortcuts", "A"),
    ("2.2.1", "Timing Adjustable", "A"),
    ("2.2.2", "Pause, Stop, Hide", "A"),
    ("2.3.1", "Three Flashes or Below Threshold", "A"),
    ("2.4.1", "Bypass Blocks", "A"),
    ("2.4.2", "Page Titled", "A"),
    ("2.4.3", "Focus Order", "A"),
    ("2.4.4", "Link Purpose (In Context)", "A"),
    ("2.4.5", "Multiple Ways", "AA"),
    ("2.4.6", "Headings and Labels", "AA"),
    ("2.4.7", "Focus Visible", "AA"),
    ("2.4.11", "Focus Not Obscured (Minimum)", "AA"),
    ("2.5.1", "Pointer Gestures", "A"),
    ("2.5.2", "Pointer Cancellation", "A"),
    ("2.5.3", "Label in Name", "A"),
    ("2.5.4", "Motion Actuation", "A"),
    ("2.5.7", "Dragging Movements", "AA"),
    ("2.5.8", "Target Size (Minimum)", "AA"),
    ("3.1.1", "Language of Page", "A"),
    ("3.1.2", "Language of Parts", "AA"),
    ("3.2.1", "On Focus", "A"),
    ("3.2.2", "On Input", "A"),
    ("3.2.3", "Consistent Navigation", "AA"),
    ("3.2.4", "Consistent Identification", "AA"),
    ("3.2.6", "Consistent Help", "A"),
    ("3.3.1", "Error Identification", "A"),
    ("3.3.2", "Labels or Instructions", "A"),
    ("3.3.3", "Error Suggestion", "AA"),
    ("3.3.4", "Error Prevention (Legal, Financial, Data)", "AA"),
    ("3.3.7", "Redundant Entry", "A"),
    ("3.3.8", "Accessible Authentication (Minimum)", "AA"),
    ("4.1.2", "Name, Role, Value", "A"),
    ("4.1.3", "Status Messages", "AA"),
]
CRITERIA: dict[str, dict[str, str]] = {num: {"id": num, "name": name, "level": lvl} for num, name, lvl in _CRITERIA}

_SC_TAG = re.compile(r"^wcag(\d)(\d)(\d{1,2})$")


def understanding_url(sc: str) -> str:
    name = CRITERIA.get(sc, {}).get("name", "")
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return f"https://www.w3.org/WAI/WCAG22/Understanding/{slug}.html" if slug else "https://www.w3.org/WAI/WCAG22/"


def criteria_from_tags(tags: list[str]) -> list[dict[str, str]]:
    """Map axe tags such as ``wcag143`` to WCAG success criteria."""
    found: list[dict[str, str]] = []
    for tag in tags:
        match = _SC_TAG.match(tag)
        if not match:
            continue
        sc = ".".join(match.groups())
        info = CRITERIA.get(sc, {"id": sc, "name": "", "level": ""})
        if all(c["id"] != sc for c in found):
            found.append({**info, "url": understanding_url(sc)})
    return found


def wcag_level_from_tags(tags: list[str]) -> str:
    """Strictest conformance level among the mapped criteria, or 'Best practice'."""
    levels = {c["level"] for c in criteria_from_tags(tags)}
    for level in ("A", "AA", "AAA"):
        if level in levels:
            return level
    return "Best practice"


# Curated, developer-facing fixes for the rules that come up most often. Anything
# not listed falls back to axe-core's own per-node guidance and help text.
REMEDIATION: dict[str, str] = {
    "color-contrast": "Increase the contrast between text and its background to at least 4.5:1 (3:1 for large "
    "text ≥ 24px, or ≥ 18.66px bold). Adjust the foreground or background colour token rather than individual "
    "elements so the fix applies site-wide.",
    "color-contrast-enhanced": "For AAA, raise text contrast to 7:1 (4.5:1 for large text).",
    "image-alt": 'Add an alt attribute to every <img>. Describe the image\'s purpose in context; use alt="" '
    "only when the image is purely decorative.",
    "input-image-alt": 'Give <input type="image"> an alt attribute describing the action it performs.',
    "role-img-alt": 'Elements with role="img" need an accessible name via aria-label or aria-labelledby.',
    "svg-img-alt": 'Give SVGs with role="img" a <title> child or an aria-label describing the graphic.',
    "label": 'Associate every form control with a visible <label for="…">, or wrap the control in its label. '
    "Placeholders are not a substitute for labels.",
    "select-name": "Give each <select> a programmatically associated <label>.",
    "link-name": "Ensure every link has discernible text. For icon-only links add visually hidden text or "
    "aria-label describing the destination.",
    "button-name": "Give every button an accessible name: visible text, aria-label, or aria-labelledby. "
    "Icon-only buttons need a text alternative.",
    "html-has-lang": 'Add a lang attribute to the <html> element, e.g. <html lang="en">.',
    "html-lang-valid": "Use a valid BCP 47 language code in the <html lang> attribute (e.g. en, en-GB, fr).",
    "valid-lang": "Use valid BCP 47 language codes in lang attributes on elements.",
    "document-title": "Add a unique, descriptive <title> that identifies the page and the site.",
    "duplicate-id-aria": "IDs referenced by ARIA attributes or labels must be unique on the page.",
    "frame-title": "Give each <iframe> a title attribute describing its content.",
    "list": "<ul> and <ol> may only directly contain <li>, <script> or <template> elements.",
    "listitem": 'Place <li> elements inside a <ul> or <ol> (or an element with role="list").',
    "definition-list": "<dl> elements may only directly contain properly-ordered <dt>/<dd> groups.",
    "meta-viewport": "Remove user-scalable=no and maximum-scale < 2 from the viewport meta tag so users can zoom.",
    "meta-refresh": 'Avoid automatic page refresh/redirect via <meta http-equiv="refresh">.',
    "aria-allowed-attr": "Remove ARIA attributes that are not permitted on the element's role.",
    "aria-required-attr": "Add the ARIA attributes required by the element's role (e.g. aria-checked for "
    'role="checkbox").',
    "aria-valid-attr": "Fix misspelled or non-existent ARIA attribute names.",
    "aria-valid-attr-value": "Ensure ARIA attribute values are valid (correct tokens, existing ID references).",
    "aria-roles": "Use only valid, non-abstract ARIA role values.",
    "aria-hidden-focus": 'Elements inside aria-hidden="true" must not be focusable. Remove them from the tab '
    'order (tabindex="-1" / inert) or remove aria-hidden.',
    "aria-hidden-body": 'Remove aria-hidden="true" from the <body> element.',
    "aria-required-children": "Elements with a composite role must contain the required owned roles "
    '(e.g. role="list" needs role="listitem" children).',
    "aria-required-parent": "Elements with roles such as listitem, option or tab must be inside their "
    "required parent role.",
    "aria-command-name": 'Give elements with role="button", "link" or "menuitem" an accessible name.',
    "aria-input-field-name": "Give ARIA input widgets (combobox, listbox, searchbox, slider…) an accessible name.",
    "aria-toggle-field-name": "Give ARIA toggle widgets (checkbox, switch, radio…) an accessible name.",
    "aria-progressbar-name": 'Give role="progressbar" an accessible name.',
    "aria-tooltip-name": 'Give role="tooltip" elements discernible text.',
    "aria-dialog-name": "Give dialogs an accessible name via aria-label or aria-labelledby.",
    "nested-interactive": "Do not nest interactive controls (e.g. a button inside a link). Restructure so each "
    "control is separate.",
    "heading-order": "Use heading levels sequentially (h1 → h2 → h3) without skipping levels to convey structure.",
    "empty-heading": "Remove empty headings or give them meaningful text.",
    "page-has-heading-one": "Add a single <h1> that describes the main content of the page.",
    "landmark-one-main": "Wrap the primary content in a single <main> element.",
    "landmark-unique": "Give repeated landmarks (e.g. multiple <nav>) unique accessible names with aria-label.",
    "landmark-no-duplicate-banner": 'Use only one top-level <header>/role="banner" per page.',
    "landmark-no-duplicate-contentinfo": 'Use only one top-level <footer>/role="contentinfo" per page.',
    "landmark-banner-is-top-level": "Do not nest the banner landmark inside another landmark.",
    "landmark-contentinfo-is-top-level": "Do not nest the contentinfo landmark inside another landmark.",
    "landmark-main-is-top-level": "Do not nest <main> inside another landmark.",
    "landmark-complementary-is-top-level": "Place <aside> at the top level rather than inside other landmarks.",
    "region": "Place all visible content inside landmark regions (header, nav, main, footer) so screen-reader "
    "users can navigate by region.",
    "bypass": 'Provide a "Skip to main content" link as the first focusable element, or use landmarks/headings '
    "so users can bypass repeated blocks.",
    "skip-link": 'Make sure the skip link\'s target (href="#id") exists and is focusable.',
    "tabindex": 'Avoid positive tabindex values; rely on DOM order and use tabindex="0" or "-1" only.',
    "target-size": "Make interactive targets at least 24×24 CSS pixels, or space them so a 24px circle around each "
    "does not overlap another target (WCAG 2.5.8).",
    "autocomplete-valid": "Use valid autocomplete tokens (e.g. email, given-name, tel) on inputs that collect "
    "personal data.",
    "link-in-text-block": "Distinguish inline links from surrounding text by more than colour alone — e.g. an "
    "underline — or ensure 3:1 contrast with surrounding text plus a non-colour cue on focus/hover.",
    "video-caption": 'Provide synchronised captions for all prerecorded video with audio (<track kind="captions">).',
    "audio-caption": "Provide a transcript or captions for audio content.",
    "object-alt": "Give <object> elements a text alternative.",
    "area-alt": "Give each <area> in an image map an alt attribute.",
    "server-side-image-map": "Replace server-side image maps with client-side maps or regular links.",
    "scrollable-region-focusable": 'Make scrollable regions keyboard-accessible: add tabindex="0" and an '
    "accessible name, or ensure they contain focusable content.",
    "td-headers-attr": "Ensure each cell's headers attribute references header cells in the same table.",
    "th-has-data-cells": "Every table header must be associated with data cells.",
    "td-has-header": "In large data tables, associate each data cell with a header using <th> and scope.",
    "empty-table-header": "Give table headers visible, meaningful text.",
    "label-title-only": "Use a visible <label> instead of relying only on title or aria-describedby.",
    "label-content-name-mismatch": "Make sure the accessible name contains the visible label text (WCAG 2.5.3).",
    "form-field-multiple-labels": "Associate each form field with only one label.",
    "blink": "Remove <blink> elements.",
    "marquee": "Remove <marquee> elements; provide pause/stop controls for any moving content.",
    "no-autoplay-audio": "Do not autoplay audio for more than 3 seconds, or provide a control to stop it.",
    "presentation-role-conflict": 'Elements with role="none"/"presentation" must not be focusable or have '
    "global ARIA attributes.",
    "image-redundant-alt": "Avoid repeating surrounding text in image alt text.",
    "identical-links-same-purpose": "Links with the same accessible name should go to the same destination, or "
    "give them distinct names.",
    "focus-order-semantics": "Elements in the focus order should have an appropriate interactive role.",
    "css-orientation-lock": "Do not lock content to portrait or landscape orientation with CSS.",
    "avoid-inline-spacing": "Do not use !important on inline letter/word/line spacing; users must be able to "
    "override text spacing.",
}


def remediation_for(rule_id: str, fallback: str) -> str:
    return REMEDIATION.get(rule_id, fallback)


# Checks that automated tools cannot reliably make. Shown on every report.
MANUAL_CHECKS = [
    {
        "id": "keyboard",
        "title": "Keyboard-only navigation",
        "criteria": ["2.1.1", "2.1.2", "2.4.3"],
        "how": "Unplug the mouse. Use Tab, Shift+Tab, Enter, Space, arrow keys and Esc to reach and operate every "
        "control, menu, modal and widget. Confirm there are no keyboard traps and the order is logical.",
    },
    {
        "id": "focus-visible",
        "title": "Visible and unobscured focus",
        "criteria": ["2.4.7", "2.4.11"],
        "how": "While tabbing, the focused element must always have a clearly visible indicator and must not be "
        "hidden behind sticky headers, cookie banners or chat widgets.",
    },
    {
        "id": "screen-reader",
        "title": "Screen reader walkthrough",
        "criteria": ["1.3.1", "4.1.2", "4.1.3"],
        "how": "Test key journeys with NVDA or JAWS (Windows), VoiceOver (macOS/iOS) and TalkBack (Android). Check "
        "that names, roles, states and dynamic status messages are announced correctly.",
    },
    {
        "id": "alt-quality",
        "title": "Quality of text alternatives",
        "criteria": ["1.1.1"],
        "how": "Automated tools only detect missing alt text. Review whether each alternative is accurate and "
        "conveys the image's purpose in context.",
    },
    {
        "id": "media",
        "title": "Captions, transcripts and audio description",
        "criteria": ["1.2.1", "1.2.2", "1.2.3", "1.2.5"],
        "how": "Check that video has accurate synchronised captions, audio has transcripts and visual-only "
        "information is described.",
    },
    {
        "id": "reflow-zoom",
        "title": "Zoom, reflow and text spacing",
        "criteria": ["1.4.4", "1.4.10", "1.4.12"],
        "how": "Zoom to 200% and 400% (320 CSS px width). Content must reflow without horizontal scrolling or loss "
        "of content. Apply the WCAG text-spacing bookmarklet and check nothing is clipped.",
    },
    {
        "id": "hover-focus-content",
        "title": "Content on hover or focus",
        "criteria": ["1.4.13"],
        "how": "Tooltips and pop-overs must be dismissible (Esc), hoverable and persistent until dismissed.",
    },
    {
        "id": "use-of-color",
        "title": "Colour is not the only cue",
        "criteria": ["1.4.1", "1.3.3"],
        "how": "Check charts, form errors, status indicators and links convey meaning with text, icons or patterns "
        "as well as colour, and that instructions don't rely only on shape, size or location.",
    },
    {
        "id": "forms-errors",
        "title": "Form errors and help",
        "criteria": ["3.3.1", "3.3.3", "3.3.4", "3.3.7"],
        "how": "Submit forms with invalid data. Errors must be identified in text, suggest corrections, and users "
        "must not be asked to re-enter information they already provided in the same process.",
    },
    {
        "id": "authentication",
        "title": "Accessible authentication",
        "criteria": ["3.3.8"],
        "how": "Login must not require a cognitive function test (e.g. transcribing a code, solving a puzzle) "
        "unless an alternative, copy-paste support or password-manager support is available.",
    },
    {
        "id": "pointer",
        "title": "Pointer gestures and dragging",
        "criteria": ["2.5.1", "2.5.2", "2.5.7"],
        "how": "Any action that uses multi-point gestures, paths or dragging (sliders, sortable lists, maps) must "
        "also work with a single pointer click/tap.",
    },
    {
        "id": "consistency",
        "title": "Consistent navigation and help",
        "criteria": ["3.2.3", "3.2.4", "3.2.6"],
        "how": "Navigation, repeated components and help mechanisms (contact links, chat) should appear in the "
        "same relative order across pages.",
    },
    {
        "id": "timing-motion",
        "title": "Timing, motion and flashing",
        "criteria": ["2.2.1", "2.2.2", "2.3.1"],
        "how": "Time limits must be adjustable; auto-moving or auto-updating content must be pausable; nothing "
        "may flash more than three times per second.",
    },
]

for _check in MANUAL_CHECKS:
    _check["criteria_detail"] = [
        {**CRITERIA[sc], "url": understanding_url(sc)} for sc in _check["criteria"] if sc in CRITERIA
    ]


# Who a failure affects, keyed by axe-core category tag.
AFFECTED_USERS = {
    "cat.color": "People with low vision or colour-vision deficiencies, and anyone reading in bright light.",
    "cat.text-alternatives": "Blind and low-vision people using screen readers or braille displays.",
    "cat.forms": "Screen-reader and voice-control users, who rely on labels to identify and operate fields.",
    "cat.keyboard": "Keyboard-only, switch-device and screen-reader users who cannot use a mouse.",
    "cat.aria": "Screen-reader and other assistive-technology users, who depend on correct ARIA semantics.",
    "cat.name-role-value": "Screen-reader and voice-control users, who need each control's name, role and state.",
    "cat.language": "Screen-reader users (speech uses the wrong pronunciation) and people using translation tools.",
    "cat.structure": "Screen-reader users who navigate by headings, lists and landmarks.",
    "cat.semantics": "Screen-reader users who navigate by headings, landmarks and other page structure.",
    "cat.tables": "Screen-reader users, who need header cells to understand data tables.",
    "cat.time-and-media": "Deaf and hard-of-hearing people, and people distracted by moving or timed content.",
    "cat.sensory-and-visual-cues": "People with low vision, colour-vision deficiencies or cognitive disabilities.",
    "cat.parsing": "Assistive-technology users, whose tools may misread malformed markup.",
}


def affected_users(tags: list[str]) -> str | None:
    for tag in tags:
        if tag in AFFECTED_USERS:
            return AFFECTED_USERS[tag]
    return None
