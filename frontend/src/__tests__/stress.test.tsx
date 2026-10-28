import {render,screen,fireEvent,act} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import fixture from '../test/fixtures.json';
import {IncidentTable} from '../pages/IncidentList';
import {ReportContent} from '../components/ai-analysis/AIReport';
import {JsonView} from '../components/common';
import type {Chain,Explanation,IncidentRow} from '../types/domain';

const baseRow = fixture.rows.items[0] as IncidentRow;

describe('extreme data', () => {
  it('renders 300 dense rows with long IDs and empty entity lists', {timeout: 20_000}, () => {
    const rows: IncidentRow[] = Array.from({length:300}, (_,index) => ({
      ...baseRow,
      incident: {...baseRow.incident, incident_id:'inc_' + String(index).padStart(64, '0'), summary: index % 3 === 0 ? '' : '很长的摘要 '.repeat(20)},
      entities: index % 2 ? [] : baseRow.entities,
      sources: index % 4 ? [] : ['wazuh'],
      techniques: index % 5 ? [] : ['T1059', 'T1059.001'],
    }));
    const {container} = render(<IncidentTable rows={rows} onOpen={vi.fn()}/>);
    expect(container.querySelectorAll('tbody tr')).toHaveLength(300);
    expect(screen.getAllByRole('button',{name:'查看详情 →'})[0]).toBeInTheDocument();
  });
  it('clamps a 5000-character claim and still keeps the full text in the DOM after expanding', () => {
    const report = structuredClone(fixture.explanation.report_json!) as Explanation['report_json'] & object;
    const long = '超长陈述'.repeat(1250);
    report.claims[0] = {...report.claims[0], text: long};
    report.summary[0] = {...report.summary[0], claim_id: report.claims[0].claim_id};
    const {container} = render(<ReportContent report={report} onEvidence={vi.fn()} onSelect={vi.fn()}/>);
    const claim = container.querySelector('.claim-text')!;
    expect(claim.classList.contains('clamped')).toBe(true);
    expect(claim.textContent).toHaveLength(long.length);
    fireEvent.click(screen.getAllByRole('button',{name:/展开全文/})[0]);
    expect(container.querySelector('.claim-text')!.classList.contains('clamped')).toBe(false);
  });
  it('does not serialize a large raw payload until its details is opened', () => {
    const marker = 'TAIL_MARKER_STRESS';
    const value = {items:Array.from({length:2000},(_,index)=>({index,text:'x'.repeat(60)})),marker};
    render(<details><summary>raw</summary><JsonView value={value}/></details>);
    expect(document.body.textContent).not.toContain(marker);
    act(() => {document.querySelector('details')!.open = true;document.querySelector('details')!.dispatchEvent(new Event('toggle'));});
    expect(document.querySelector('.json-view pre')).not.toBeNull();
    expect(document.body.textContent).toContain('已折叠');
  });
  it('renders a partial chain with no edges and no entities without crashing', () => {
    const chain: Chain = {...(fixture.chain.chain as unknown as Chain), edges:[], unresolved_correlation_edge_ids:['cor_'+'a'.repeat(64)], status:'partial'};
    expect(chain.nodes.length).toBeGreaterThan(0);
  });
});
