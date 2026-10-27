import {afterEach, describe, expect, it, vi} from 'vitest';
import {cleanup, fireEvent, render, screen, waitFor} from '@testing-library/react';
import {api} from '../api/client';
import App from '../App';
import {StageAnalysisView, StageGraph} from '../pages/StageWorkbench';
import {flowRelations, layoutStageFlow} from '../lib/stageFlow';
import type {StageAnalysis} from '../types/stageAnalysis';

const aid='ana_'+'a'.repeat(64);
const data: StageAnalysis = {
  analysis_id:aid, algorithm_version:'stage-attack-chain-v1', status:'sealed',
  counts:{input_count:125,stage_count:2,relation_count:3,chain_count:1,strong_directed_count:1,strong_undirected_count:1,weak_directed_count:1},
  chains:[{chain_id:'chain',community_id:'community',stage_ids:['first','second'],relation_ids:['strong','weak','undirected'],stage_count:2,relation_count:3,strong_directed_count:1,strong_undirected_count:1,weak_directed_count:1,single_stage:false,has_directed_cycle:false,entry_stage_ids:[],exit_stage_ids:[]}],
  stages:[{stage_id:'first',community_id:'community',behavior:'AUTHENTICATION',start_time:'2026-10-19T01:00:00Z',end_time:'2026-10-19T01:00:00Z',alert_ids:['alert'],alert_count:1,source_types:['edr'],evidence_summary:'observed'}, {stage_id:'second',community_id:'community',behavior:'PROCESS_EXECUTION',start_time:'2026-10-19T01:00:05Z',end_time:'2026-10-19T01:00:05Z',alert_ids:['other'],alert_count:1,source_types:['waf'],evidence_summary:'observed'}],
  relations:[{relation_id:'strong',stage_a_id:'first',stage_b_id:'second',from_stage_id:'second',to_stage_id:'first',relation_type:'STRONG_DIRECTED',direction_basis:'evidence_semantics',confidence:0.9,evidence_type:'direct_reference',reason:'semantic direction',witness_alert_ids:['alert','other']}, {relation_id:'weak',stage_a_id:'first',stage_b_id:'second',from_stage_id:'first',to_stage_id:'second',relation_type:'WEAK_DIRECTED',direction_basis:'temporal_order',confidence:0.5,evidence_type:'shared_binding',reason:'temporal only',witness_alert_ids:['alert','other']}, {relation_id:'undirected',stage_a_id:'first',stage_b_id:'second',from_stage_id:null,to_stage_id:null,relation_type:'STRONG_UNDIRECTED',direction_basis:'unresolved',confidence:0.8,evidence_type:'direct_reference',reason:'direction conflict',witness_alert_ids:['alert','other']}],
};

afterEach(()=>{cleanup();vi.restoreAllMocks();history.replaceState({},'', '/');});

describe('Stage workbench',()=>{
  it('counts undirected associations in event summaries and explains a single-stage zero',()=>{
    const onlyUndirected={...data,chains:[{...data.chains[0],strong_directed_count:0,strong_undirected_count:1,weak_directed_count:0}]};
    const {unmount}=render(<StageAnalysisView data={onlyUndirected}/>);
    expect(screen.getByRole('button',{name:/事件 1/})).toHaveTextContent('1 强关联 / 0 弱时间');
    expect(screen.getByRole('button',{name:/事件 1/})).toHaveTextContent('0 有向 · 1 无向');
    unmount();
    render(<StageAnalysisView data={{...data,chains:[{...data.chains[0],single_stage:true,
      stage_ids:['first'],stage_count:1,relation_ids:[],relation_count:0,strong_directed_count:0,strong_undirected_count:0,weak_directed_count:0}]}}/>);
    expect(screen.getByText(/强关联数统计阶段之间的关系/)).toHaveTextContent('1 条告警已聚合为一个阶段');
  });
  it('opens the overview on the home page and stage detail via view=stages without a typed ID',async()=>{
    vi.spyOn(api,'stageCatalog').mockResolvedValue({default_analysis_id:aid,items:[{analysis_id:aid,input_count:125,algorithm_version:data.algorithm_version}]});
    vi.spyOn(api,'stageAnalysis').mockResolvedValue(data);
    vi.spyOn(api,'stageSummary').mockResolvedValue({analysis_id:aid,summary:{counts:{input_count:125,kept_count:125,stage_count:2,host_count:1},source_type:[],source_namespace:[],source_product:[],hosts:[],behavior:[],time_series:[]}});
    const legacy=vi.spyOn(api,'overview');
    history.replaceState({},'', '/');
    const {unmount}=render(<App/>);
    expect(await screen.findByRole('heading',{name:'安全运营态势总览'})).toBeInTheDocument();
    expect(screen.queryByLabelText('分析 ID')).not.toBeInTheDocument();
    expect(legacy).not.toHaveBeenCalled();
    unmount();
    history.replaceState({},'', '/?view=stages');
    render(<App/>);
    expect(await screen.findByRole('heading',{name:'125 条告警分析'})).toBeInTheDocument();
  });
  it('preserves semantic backward direction and renders no arrow for undirected relations',()=>{
    const select=vi.fn();const {container}=render(<StageGraph stages={data.stages} relations={data.relations} selected="" onSelect={select}/>);
    const strong=container.querySelector('[data-source="second"]')!;
    expect(strong).toHaveAttribute('data-target','first');
    expect(container.querySelector('[data-source=""] .edge-line')).not.toHaveAttribute('marker-end');
    expect(screen.getByRole('button',{name:/查看弱时间关系证据/})).toBeInTheDocument();
    fireEvent.keyDown(strong,{key:'Enter'});expect(select).toHaveBeenCalledWith('strong');
  });
  it('resolves selected evidence and only requests raw after an explicit click',async()=>{
    vi.spyOn(api,'stageTrace').mockResolvedValue({analysis_id:aid,trace:{subject_id:'first',evidence_summary:'real evidence',witness_alert_ids:['alert'],winning_witness_alert_ids:[],witness_alerts:[{alert_id:'alert',source_type:'edr',timestamp:'2026-10-19T01:00:00Z',signature:null,alert_type:null}]},resolved_pointers:[{alert_id:'alert',pointer:'/host',value:'host-a'}]});
    const raw=vi.spyOn(api,'stageRaw').mockResolvedValue({raw_alert:{content:'<img src=x onerror=alert(1)>'}});
    render(<StageAnalysisView data={data}/>);
    expect(screen.getByRole('button',{name:/事件 1/})).toBeInTheDocument();
    const scroll=vi.spyOn(window,'scrollTo');
    fireEvent.click(screen.getByRole('button',{name:'阶段列表'}));
    fireEvent.click(screen.getAllByRole('button',{name:'查看阶段证据'})[0]);
    expect(screen.getByRole('dialog',{name:/阶段证据/})).toBeInTheDocument();
    expect(document.body.style.overflow).toBe('hidden');
    expect(scroll).not.toHaveBeenCalled();
    await screen.findByText('real evidence');expect(raw).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button',{name:'查看原始告警'}));
    await waitFor(()=>expect(raw).toHaveBeenCalledWith(aid,'alert',expect.any(AbortSignal)));
    expect(await screen.findByText(/<img src=x/)).toBeInTheDocument();
    expect(document.querySelector('img')).toBeNull();
    fireEvent.click(screen.getByRole('button',{name:'关闭证据'}));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(document.body.style.overflow).not.toBe('hidden');
  });
  it('shows the entire event including downstream stages without choosing a focus or paging',()=>{
    const third={...data.stages[1],stage_id:'third'};
    const downstream={...data.relations[0],relation_id:'downstream',stage_a_id:'first',stage_b_id:'third',from_stage_id:'first',to_stage_id:'third'};
    const {container}=render(<StageGraph stages={[...data.stages,third]} relations={[data.relations[0],downstream]} selected="" onSelect={vi.fn()}/>);
    expect(container.querySelectorAll('[data-stage-id]')).toHaveLength(3);
    expect(screen.getByRole('button',{name:/证据 downstream/})).toBeInTheDocument();
    expect(screen.queryByRole('button',{name:'下一页'})).not.toBeInTheDocument();
    expect(screen.queryByRole('button',{name:/选择阶段/})).not.toBeInTheDocument();
    const layout=layoutStageFlow([...data.stages,third],[data.relations[0],downstream]);
    const ranks=new Map(layout.nodes.map(n=>[n.stage.stage_id,n.rank]));
    expect(ranks.get('second')!).toBeLessThan(ranks.get('first')!);
    expect(ranks.get('first')!).toBeLessThan(ranks.get('third')!);
  });
  it('folds only same-kind redundant paths and restores every original relation on expansion',()=>{
    const third={...data.stages[1],stage_id:'third'};
    const first={...data.relations[1],relation_id:'a'};
    const next={...first,relation_id:'b',stage_a_id:'second',stage_b_id:'third',from_stage_id:'second',to_stage_id:'third'};
    const shortcut={...first,relation_id:'c',stage_b_id:'third',to_stage_id:'third'};
    const semantic={...shortcut,relation_id:'d',relation_type:'STRONG_DIRECTED' as const};
    const differentEvidence={...shortcut,relation_id:'e',evidence_type:'shared_process_instance'};
    const relations=[first,next,shortcut,semantic,differentEvidence];
    expect(flowRelations(relations).map(r=>r.relation_id)).toEqual(['a','b','d','e']);
    const {container}=render(<StageGraph stages={[...data.stages,third]} relations={relations} selected="" onSelect={vi.fn()}/>);
    expect(container.querySelectorAll('.graph-edge')).toHaveLength(4);
    fireEvent.click(screen.getByLabelText('展开全部关系'));
    expect(container.querySelectorAll('.graph-edge')).toHaveLength(5);
    expect(container.querySelectorAll('.graph-node')).toHaveLength(3);
  });
  it('retains cycles, isolated stages and single-stage events without inventing connections',()=>{
    const isolated={...data.stages[0],stage_id:'isolated'};
    const reverse={...data.relations[0],relation_id:'reverse',from_stage_id:'first',to_stage_id:'second'};
    const self={...reverse,relation_id:'self',stage_b_id:'first',to_stage_id:'first'};
    const layout=layoutStageFlow([...data.stages,isolated],[data.relations[0],reverse,self]);
    expect(layout.hasCycle).toBe(true);
    expect(layout.nodes).toHaveLength(3);
    expect(new Set(layout.nodes.map(n=>`${n.x},${n.y}`)).size).toBe(3);
    expect(flowRelations([data.relations[0],reverse,self])).toHaveLength(3);
    const {container}=render(<StageGraph stages={[isolated]} relations={[]} selected="" onSelect={vi.fn()}/>);
    expect(container.querySelectorAll('.graph-node')).toHaveLength(1);
    expect(container.querySelectorAll('.graph-edge')).toHaveLength(0);
    expect(screen.getByText(/没有跨阶段连线/)).toBeInTheDocument();
  });
});
