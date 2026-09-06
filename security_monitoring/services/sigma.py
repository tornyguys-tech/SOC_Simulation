from pathlib import Path
from typing import List, Dict, Any, Optional
import yaml


RULES_DIR = Path(__file__).resolve().parent.parent / "sigma_rules"


def load_all_rules() -> List[Dict[str, Any]]:
    """Loads and parses all Sigma YAML rules from the rules directory."""
    rules = []
    if not RULES_DIR.exists():
        return rules

    for file_path in sorted(RULES_DIR.glob("*.yml")):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                raw_yaml = f.read()
                data = yaml.safe_load(raw_yaml)
                if isinstance(data, dict):
                    data["_raw_yaml"] = raw_yaml
                    data["_file_path"] = str(file_path)
                    rules.append(data)
        except Exception as e:
            continue
    return rules


def evaluate_field_condition(event_val: Any, rule_val: Any, modifier: Optional[str] = None) -> bool:
    """Evaluates a single field check against an event value with optional modifiers."""
    if event_val is None:
        return False

    str_event = str(event_val).lower()
    str_rule = str(rule_val).lower()

    if modifier == "startswith":
        return str_event.startswith(str_rule)
    elif modifier == "endswith":
        return str_event.endswith(str_rule)
    elif modifier == "contains":
        return str_rule in str_event
    else:
        # Exact match or list contains
        if isinstance(rule_val, list):
            return any(str(item).lower() == str_event for item in rule_val)
        return str_event == str_rule


def evaluate_selection(selection_dict: Dict[str, Any], event_data: Dict[str, Any]) -> bool:
    """Checks if all field requirements in a selection block match the event."""
    for field_spec, expected_val in selection_dict.items():
        if "|" in field_spec:
            field_name, modifier = field_spec.split("|", 1)
        else:
            field_name, modifier = field_spec, None

        event_val = event_data.get(field_name)
        if not evaluate_field_condition(event_val, expected_val, modifier):
            return False
    return True


def evaluate_sigma_rules(event_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Evaluates all loaded Sigma rules against the given event dictionary.
    Returns list of matched rule details.
    """
    matched_rules = []
    rules = load_all_rules()

    for rule in rules:
        title = rule.get("title", "Untitled Rule")
        rule_id = rule.get("id", "")
        level = rule.get("level", "medium").upper()
        detection = rule.get("detection", {})
        selection = detection.get("selection", {})

        if not selection:
            continue

        if evaluate_selection(selection, event_data):
            matched_rules.append({
                "title": title,
                "id": rule_id,
                "level": level,
                "description": rule.get("description", ""),
                "author": rule.get("author", "ThreatLens SOC Team"),
                "raw_yaml": rule.get("_raw_yaml", ""),
                "tags": rule.get("tags", []),
                "matched_selection": selection
            })

    return matched_rules
