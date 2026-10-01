#!/usr/bin/env python3
"""Build an importable Icinga Director basket from the field source file."""

import json
import pathlib
import uuid


ROOT = pathlib.Path(__file__).parents[1]
SOURCE = ROOT / "tools" / "check_opnsense-basket.source.json"
TARGET = ROOT / "director" / "check_opnsense-basket.json"
NAMESPACE = uuid.UUID("74632ca2-7942-47c0-a3d4-73924a3a9026")


def object_uuid(name):
    return str(uuid.uuid5(NAMESPACE, name))


def service_object(name, template_name):
    return {
        "action_url": None,
        "apply_for": None,
        "assign_filter": None,
        "check_command": None,
        "check_interval": None,
        "check_period": None,
        "check_timeout": None,
        "command_endpoint": None,
        "disabled": False,
        "display_name": name,
        "enable_active_checks": None,
        "enable_event_handler": None,
        "enable_flapping": None,
        "enable_notifications": None,
        "enable_passive_checks": None,
        "enable_perfdata": None,
        "event_command": None,
        "fields": [],
        "flapping_threshold_high": None,
        "flapping_threshold_low": None,
        "groups": [],
        "host": None,
        "icon_image": None,
        "icon_image_alt": None,
        "imports": [template_name],
        "max_check_attempts": None,
        "notes": None,
        "notes_url": None,
        "object_name": name,
        "object_type": "object",
        "retry_interval": None,
        "service_set": "OPNsense Monitoring",
        "template_choice": None,
        "use_agent": None,
        "use_var_overrides": None,
        "vars": {},
        "volatile": None,
        "zone": None,
        "uuid": object_uuid("Service:" + name),
    }


def main():
    source = json.loads(SOURCE.read_text())
    wrapped = source["Director Config"]["objects"]

    categories = {}
    for name, item in wrapped.get("DatafieldCategory", {}).items():
        categories[name] = {
            "category_name": item["category_name"],
            "description": "OPNsense monitoring fields",
        }

    datafields = {}
    field_ids = {}
    for field_id, (name, item) in enumerate(wrapped["Datafield"].items(), 1):
        field_ids[name] = field_id
        datafields[str(field_id)] = {
            "category": item.get("category"),
            "varname": item["varname"],
            "caption": item["caption"],
            "description": item.get("description"),
            "datatype": item["datatype"],
            "format": item.get("format"),
            "settings": item.get("settings", {}),
            "uuid": object_uuid("Datafield:" + name),
        }

    old_command = wrapped["CheckCommand"]["check_opnsense"]
    arguments = {}
    for name, definition in old_command["arguments"].items():
        arguments[name] = definition if isinstance(definition, dict) else {"value": definition}

    command = {
        "arguments": arguments,
        "command": "/usr/lib/nagios/plugins/check_opnsense.py",
        "disabled": False,
        "fields": [
            {"datafield_id": field_id, "is_required": "n", "var_filter": None}
            for field_id in field_ids.values()
        ],
        "imports": [],
        "is_string": None,
        "methods_execute": "PluginCheck",
        "object_name": "check_opnsense",
        "object_type": "object",
        "timeout": "60",
        "vars": {},
        "zone": None,
        "uuid": object_uuid("Command:check_opnsense"),
    }

    old_template = wrapped["ServiceTemplate"]["OPNsense Service Master"]
    master_template = {
        "action_url": None,
        "apply_for": None,
        "assign_filter": None,
        "check_command": "check_opnsense",
        "check_interval": 300,
        "check_period": None,
        "check_timeout": None,
        "command_endpoint": None,
        "disabled": False,
        "display_name": None,
        "enable_active_checks": True,
        "enable_event_handler": None,
        "enable_flapping": None,
        "enable_notifications": True,
        "enable_passive_checks": None,
        "enable_perfdata": True,
        "event_command": None,
        "fields": [],
        "flapping_threshold_high": None,
        "flapping_threshold_low": None,
        "groups": [],
        "host": None,
        "icon_image": None,
        "icon_image_alt": None,
        "imports": [],
        "max_check_attempts": old_template["max_check_attempts"],
        "notes": "API monitoring for OPNsense 24.7 through 26.x",
        "notes_url": None,
        "object_name": "OPNsense Service Master",
        "object_type": "template",
        "retry_interval": 60,
        "service_set": None,
        "template_choice": None,
        "use_agent": None,
        "use_var_overrides": None,
        "vars": old_template["vars"],
        "volatile": None,
        "zone": None,
        "uuid": object_uuid("ServiceTemplate:OPNsense Service Master"),
    }

    service_modes = {
        "OPNsense CPU": "cpu",
        "OPNsense Memory": "memory",
        "OPNsense Disk": "disk",
        "OPNsense Services": "services",
        "OPNsense Updates": "updates",
        "OPNsense Certificates": "certificates",
        "OPNsense Interfaces": "interfaces",
        "OPNsense WireGuard": "wireguard",
        "OPNsense Firewall": "firewall",
    }
    templates = {"OPNsense Service Master": master_template}
    template_names = {}
    for service_name, mode in service_modes.items():
        template_name = service_name + " Template"
        template_names[service_name] = template_name
        templates[template_name] = {
            **master_template,
            "check_command": None,
            "display_name": None,
            "imports": ["OPNsense Service Master"],
            "notes": f"OPNsense {mode} check",
            "object_name": template_name,
            "vars": {"opnsense_mode": mode},
            "uuid": object_uuid("ServiceTemplate:" + template_name),
        }

    service_set = {
        "assign_filter": None,
        "description": "Complete API monitoring for OPNsense systems",
        "host": None,
        "object_name": "OPNsense Monitoring",
        "object_type": "template",
        "uuid": object_uuid("ServiceSet:OPNsense Monitoring"),
    }
    service_set["services"] = [
        service_object(name, template_names[name])
        for name in service_modes
    ]

    basket = {
        "Command": {"check_opnsense": command},
        "ServiceTemplate": templates,
        "ServiceSet": {"OPNsense Monitoring": service_set},
        "Datafield": datafields,
        "DatafieldCategory": categories,
    }
    TARGET.write_text(json.dumps(basket, indent=4, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
