import {render,screen,within} from '@testing-library/react';
import {it,expect,vi} from 'vitest';
import Dashboard from '../pages/Dashboard';
import {IncidentTable} from '../pages/IncidentList';
import {ScoreDiagnostic} from '../components/ScoreDiagnostic';
import {api} from '../api/client';
import {categoryLabel,severityLabel,statusLabel} from '../lib/displayLabels';
import fixture from '../test/fixtures.json';
import type {IncidentRow,Overview,ScoreDiagnosticData} from '../types/domain';

it('uses representative projections and Chinese labels without changing API enums',async()=>{
  const data=structuredClone(fixture.overview) as Overview;
  data.counts={...data.counts,singleton_count:99,multi_alert_count:99,
    representative_singleton_incident_count:1,correlated_multi_alert_incident_count:0,incidents_with_dedupe_expansion_count:1};
  data.distributions.severity=['low','medium','high','unknown'].map(value=>({value,count:1}));
  data.status='completed';const before=JSON.stringify(data);
  vi.spyOn(api,'overview').mockResolvedValue(data);const {container}=render(<Dashboard analysisId={fixture.analysisId}/>);
  await screen.findByText('安全事件工作台');
  for(const text of ['标准化告警','冻结分析快照','分析完成','低','中','高','未知'])expect(screen.getByText(text,{exact:true})).toBeInTheDocument();
  for(const text of ['CanonicalAlert','FROZEN ANALYSIS','Analysis Diagnostics'])expect(screen.queryByText(text)).not.toBeInTheDocument();
  expect(screen.getByText('分析诊断与复核配置')).toBeInTheDocument();
  expect(within([...container.querySelectorAll('.metric')].find(m=>m.textContent?.includes('关联聚合事件')) as HTMLElement).getByText('0')).toBeInTheDocument();
  expect(JSON.stringify(data)).toBe(before);
});

it('labels two expanded canonical members as a singleton when there is one representative',()=>{
  const row={...fixture.rows.items[0],representative_member_count:1,expanded_member_count:2,alert_count:2,has_dedupe_expansion:true} as IncidentRow;
  render(<IncidentTable rows={[row]} onOpen={vi.fn()}/>);
  expect(screen.getByText('单代表告警事件',{exact:true})).toBeInTheDocument();
  expect(screen.getByText('含去重展开')).toBeInTheDocument();
  expect(screen.queryByText('关联聚合事件',{exact:true})).not.toBeInTheDocument();
});

it('shows receipt scores and conditionally supported zero-edge explanation',()=>{
  const data:ScoreDiagnosticData={status:'available',conclusion:'合成诊断测试',threshold:.65,observed_max:.54,dataset_reachable_max:.54,
    theoretical_config_max:.9,threshold_gap:.11,scored_candidate_count:120,passed_threshold_count:0,
    candidate_generation_check:{bottleneck:'NO'},top_candidates:[{score:.54,contributions:{time:.2,entity:.26,behavior:.08,relation:0}}],
    missing_evidence:['合成关系缺口'],counterfactual:{summary:'假设新增核验关系；未写入事实'}};
  const {rerender}=render(<ScoreDiagnostic data={data}/>);
  expect(screen.getByText('显式传播关系')).toBeInTheDocument();
  expect(screen.getByText('已评分候选')).toBeInTheDocument();
  expect(screen.getByText(/已核验候选剪枝不会遗漏/)).toBeInTheDocument();
  expect(screen.getByText('合成关系缺口')).toBeInTheDocument();
  rerender(<ScoreDiagnostic data={{...data,candidate_generation_check:{bottleneck:'UNPROVEN'}}}/>);
  expect(screen.queryByText(/已核验候选剪枝不会遗漏/)).not.toBeInTheDocument();
});

it('unknown display enums have a stable fallback',()=>{
  expect(severityLabel('future_severity')).toBe('future_severity');
  expect(categoryLabel('future_category')).toBe('future_category');
  expect(statusLabel('future_status')).toBe('future_status');
});
