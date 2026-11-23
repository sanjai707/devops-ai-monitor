from datetime import datetime, timezone


UTC_FORMAT = "%Y-%m-%dT%H:%M:%SZ"


def utc_now():
    return datetime.now(timezone.utc).strftime(UTC_FORMAT)


class IncidentManager:
    def __init__(self, database, on_incident=None):
        self.database = database
        self.on_incident = on_incident

    def open_or_update(self, fingerprint, container_id, container_name, incident_type,
                       severity, title, evidence):
        existing = self.database.find_active_by_fingerprint(fingerprint)
        now = utc_now()
        if existing:
            if existing["severity"] != severity or existing["title"] != title:
                updated = self.database.update(existing["id"], severity, title, evidence, now)
                if self.on_incident:
                    self.on_incident(updated["id"], force=True)
                return updated
            return existing

        incident = self.database.create({
            "fingerprint": fingerprint,
            "container_id": container_id,
            "container_name": container_name,
            "type": incident_type,
            "severity": severity,
            "title": title,
            "status": "open",
            "evidence": evidence,
            "created_at": now,
            "updated_at": now,
            "acknowledged_at": None,
            "resolved_at": None,
        })
        if self.on_incident:
            self.on_incident(incident["id"])
        return incident

    def resolve(self, fingerprint):
        self.database.resolve_by_fingerprint(fingerprint, utc_now())

    def acknowledge(self, incident_id):
        return self.database.update_status(incident_id, "acknowledged", utc_now())

    def resolve_by_id(self, incident_id):
        return self.database.update_status(incident_id, "resolved", utc_now())

    def investigating(self, incident_id):
        return self.database.update_status(incident_id, "investigating", utc_now())

    def reopen(self, incident_id):
        return self.database.update_status(incident_id, "reopened", utc_now())

    def suppress(self, incident_id, comment=None, actor="operator"):
        incident = self.database.update_status(incident_id, "suppressed", utc_now())
        if incident and comment:
            incident = self.database.add_incident_comment(
                incident_id, comment[:2000], actor[:80]
            )
        return incident
