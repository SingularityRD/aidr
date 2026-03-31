import type { Incident } from "./types.js";

export interface IncidentRecordV1 {
	type: "incident_record";
	schema_version: 1;
	incident: Incident;
}

export function toIncidentRecordV1(incident: Incident): IncidentRecordV1 {
	return {
		type: "incident_record",
		schema_version: 1,
		incident,
	};
}
