import {describe,it,expect} from 'vitest';
import {incidentsToCsv} from '../lib/csv';
import fixture from '../test/fixtures.json';
import type {IncidentRow} from '../types/domain';

describe('CSV export', () => {
  it('keeps stable IDs exact and escapes commas/quotes', () => {
    const row = {...fixture.rows.items[0], incident:{...fixture.rows.items[0].incident, summary:'含,逗号与"引号"'}} as IncidentRow;
    const csv = incidentsToCsv([row]);
    expect(csv.startsWith('\uFEFF')).toBe(true);
    expect(csv).toContain(row.incident.incident_id);
    expect(csv).toContain('"含,逗号与""引号"""');
    expect(csv.split('\r\n')).toHaveLength(2);
  });
});
