import type {IncidentRow} from '../types/domain';
import {incidentKindLabel, severityLabel, statusLabel} from './displayLabels';

const escapeCell = (value: unknown): string => {
  const text = String(value ?? '');
  return /[",\n\r]/.test(text) ? '"' + text.replaceAll('"', '""') + '"' : text;
};

/** CSV for the currently loaded page only; raw IDs stay exact. */
export function incidentsToCsv(rows: IncidentRow[]): string {
  const header = ['incident_id', 'severity', 'status', 'summary', 'start_time', 'end_time', 'representative_members', 'expanded_alerts', 'node_count', 'edge_count', 'sources', 'entities', 'ai_state', 'techniques'];
  const lines = rows.map(row => [
    row.incident.incident_id,
    severityLabel(row.incident.severity),
    statusLabel(row.incident.status),
    row.incident.summary ?? '',
    row.incident.start_time,
    row.incident.end_time,
    row.representative_member_count ?? '',
    row.expanded_member_count ?? row.alert_count,
    row.node_count,
    row.edge_count,
    row.sources.join('|'),
    row.entities.map(entity => `${entity.type}:${entity.display_value ?? entity.value}`).join('|'),
    row.ai_state,
    row.techniques.join('|'),
  ].map(escapeCell).join(','));
  // BOM keeps Chinese readable in Excel on Windows.
  return '\uFEFF' + [header.join(','), ...lines].join('\r\n');
}

export function downloadTextFile(filename: string, text: string, mime = 'text/csv;charset=utf-8') {
  const url = URL.createObjectURL(new Blob([text], {type: mime}));
  const link = document.createElement('a');
  link.href = url; link.download = filename; link.click();
  URL.revokeObjectURL(url);
}
