import {afterEach, expect, it, vi} from 'vitest';
import {cleanup, fireEvent, render, screen} from '@testing-library/react';
import {StageAIReport} from '../components/StageAIReport';
import {api} from '../api/client';
import type {StageAIResult} from '../types/stageAnalysis';

const fact={fact_id:'f1',description:'原始命令行="<script>payload</script>"',evidence_refs:['alt_1'],field_refs:[{alert_id:'alt_1',pointer:'/command_line',value:'<script>payload</script>'}]};
const result:StageAIResult={analysis_id:'a1',chain_id:'c1',status:'available',grounding_status:'validated',report_markdown:'validated',report_json:{chain_id:'c1',stages:[{stage_id:'s1',observed_facts:[fact],behavior_interpretation:{description:'疑似服务上下文命令执行；不能确认服务器失陷。',confidence:.6},missing_evidence:['缺少执行结果'],risk_analysis:{potential_impact:['可能提供系统操作能力'],confirmed_impact:[]}}],relations:[{relation_id:'r1',relation_type:'UNDIRECTED_EDGE',direction_status:'UNRESOLVED',relation_explanation:'两个阶段有关联，方向仍未解决。',supporting_evidence:[],limitations:['不能按时间定向']}],chain_summary:{summary:'保留一个无向关系，方向仍未解决。',main_observed_activities:[fact],potential_overall_impact:['可能存在未授权操作风险'],confirmed_overall_impact:[],uncertainties:['证据不充分']}}};
afterEach(()=>{cleanup();vi.restoreAllMocks();});

it('loads a saved report without calling a model and keeps source content as text',async()=>{
  vi.spyOn(api,'stageAISaved').mockResolvedValue({result});
  const call=vi.spyOn(api,'stageExplain'), evidence=vi.fn();
  render(<StageAIReport analysisId="a1" chainId="c1" onEvidence={evidence}/>);
  await screen.findByText('保留一个无向关系，方向仍未解决。');
  expect(call).not.toHaveBeenCalled();
  expect(screen.getAllByText(fact.description)).toHaveLength(2);
  expect(document.querySelector('script')).toBeNull();
  expect(screen.getByText('UNDIRECTED_EDGE · UNRESOLVED')).toBeInTheDocument();
  fireEvent.click(screen.getAllByRole('button',{name:'alt_1'})[0]);
  expect(evidence).toHaveBeenCalledWith('alt_1');
  expect(screen.getAllByText('无证据支持的已确认后果。')).toHaveLength(2);
});

it('contains model failure and does not display rejected draft content',async()=>{
  vi.spyOn(api,'stageAISaved').mockResolvedValue({result:null});
  const explain=vi.spyOn(api,'stageExplain').mockResolvedValue({...result,status:'unavailable',grounding_status:'rejected',report_json:null,report_markdown:null});
  render(<StageAIReport analysisId="a1" chainId="c1" onEvidence={vi.fn()}/>);
  fireEvent.click(screen.getByRole('button',{name:'生成 AI 研判'}));
  await screen.findByText('AI 辅助研判暂不可用');
  expect(explain).toHaveBeenCalledWith('a1','c1');
  expect(screen.queryByText(fact.description)).not.toBeInTheDocument();
});

it('rejects a saved report from another chain or without validated grounding',async()=>{
  vi.spyOn(api,'stageAISaved').mockResolvedValue({result:{...result,chain_id:'other'}});
  const {unmount}=render(<StageAIReport analysisId="a1" chainId="c1" onEvidence={vi.fn()}/>);
  await screen.findByRole('button',{name:'生成 AI 研判'});
  expect(screen.queryByText(result.report_json!.chain_summary.summary)).not.toBeInTheDocument();
  unmount();
  vi.mocked(api.stageAISaved).mockResolvedValue({result:{...result,grounding_status:'rejected'}});
  render(<StageAIReport analysisId="a1" chainId="c1" onEvidence={vi.fn()}/>);
  await screen.findByRole('button',{name:'生成 AI 研判'});
  expect(screen.queryByText(fact.description)).not.toBeInTheDocument();
});
