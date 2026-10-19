import {componentLabel} from '../lib/displayLabels';
import {render,renderHook,act,screen,fireEvent,waitFor,within} from '@testing-library/react';
import {describe,it,expect,vi} from 'vitest';
import fixtureJSON from '../test/fixtures.json';
import {api} from '../api/client';
import {useResource} from '../api/hooks';
import {ChainGraph} from '../components/attack-chain/ChainGraph';
import {NodeDetail,EdgeDetailPanel} from '../components/attack-chain/ObjectDetail';
import {EvidencePanel} from '../components/evidence/EvidencePanel';
import {AIReport,ReportContent,verifiedReport} from '../components/ai-analysis/AIReport';
import {JsonView} from '../components/common';
import IncidentList,{IncidentTable} from '../pages/IncidentList';
import Dashboard from '../pages/Dashboard';
import IncidentDetail from '../pages/IncidentDetail';
import App from '../App';
import type {AlertDetail,Chain,EdgeDetail,Explanation,IncidentDetail as Detail,IncidentRow,Overview,Page,Report,SavedExplanation} from '../types/domain';

const f = fixtureJSON as unknown as {analysisId:string;incidentId:string;rows:Page<IncidentRow>;chain:{analysis_id:string;chain:Chain;diagnostics_ref:string};detail:Detail;overview:Overview;alert:AlertDetail;edge:EdgeDetail;explanation:Explanation;saved:SavedExplanation};
const filters = {page:1,kind:'all',sort:'time',severity:''};

describe('Incident workbench',() => {
  it('shows production counts, entities, source, singleton and chain statuses',() => {
    const singleton = {...f.rows.items[0],incident:{...f.rows.items[0].incident,incident_id:'single'},alert_count:1,representative_member_count:1,expanded_member_count:1,node_count:1,edge_count:0};
    const open = vi.fn();render(<IncidentTable rows={[f.rows.items[0],singleton]} onOpen={open}/>);
    expect(screen.getByText('单代表告警事件')).toBeInTheDocument();expect(screen.getByText('有向攻击链')).toBeInTheDocument();
    fireEvent.click(screen.getAllByRole('button',{name:'查看详情 →'})[0]);expect(open).toHaveBeenCalledWith(f.incidentId);
  });
  it('applies global filters and paginates through the API',async() => {
    vi.spyOn(api,'incidents').mockResolvedValue({...f.rows,total:45});const change=vi.fn();
    render(<IncidentList analysisId={f.analysisId} filters={filters} revision={0} onFilters={change} onOpen={vi.fn()}/>);
    await screen.findByText('有向攻击链');fireEvent.change(screen.getByLabelText('事件类型'),{target:{value:'singleton'}});
    expect(change).toHaveBeenCalledWith({...filters,kind:'singleton'});fireEvent.click(screen.getByText('下一页'));expect(change).toHaveBeenCalledWith({...filters,page:2});
    expect(api.incidents).toHaveBeenCalledWith(f.analysisId,1,'all','time','',expect.any(AbortSignal));
  });
  it('shows zero Incident as a valid empty state',async() => {vi.spyOn(api,'incidents').mockResolvedValue({items:[],page:1,page_size:20,total:0});render(<IncidentList analysisId={f.analysisId} filters={filters} revision={0} onFilters={vi.fn()} onOpen={vi.fn()}/>);expect(await screen.findByText('当前筛选下没有安全事件。')).toBeInTheDocument();});
  it('shows loading and errors without a blank page',async() => {vi.spyOn(api,'incidents').mockRejectedValue(new Error('snapshot_integrity_error'));render(<IncidentList analysisId={f.analysisId} filters={filters} revision={0} onFilters={vi.fn()} onOpen={vi.fn()}/>);expect(screen.getByText('正在读取安全事件列表…')).toBeInTheDocument();expect(await screen.findByRole('alert')).toHaveTextContent('snapshot_integrity_error');});
  it('dashboard uses backend projection counts including representative count',async() => {vi.spyOn(api,'overview').mockResolvedValue(f.overview);render(<Dashboard analysisId={f.analysisId}/>);await screen.findByText('安全事件工作台');expect(screen.getByText('去重代表')).toBeInTheDocument();expect(screen.getByText('设备观测等级')).toBeInTheDocument();});
});

describe('Chain rendering and selection',() => {
  it('renders exactly the accepted nodes and the direction from source to target',() => {
    const select=vi.fn();const {container}=render(<ChainGraph chain={f.chain.chain} entities={f.detail.entities} selection={null} onSelect={select}/>);
    expect(screen.getAllByRole('button',{name:/选择节点/})).toHaveLength(2);expect(screen.getAllByRole('button',{name:/选择边/})).toHaveLength(1);
    const edge=container.querySelector('[data-source]')!;expect(edge.getAttribute('data-source')).toBe(f.edge.edge.source_node_id);expect(edge.getAttribute('data-target')).toBe(f.edge.edge.target_node_id);
    fireEvent.click(edge);expect(select).toHaveBeenCalledWith({kind:'edge',id:f.edge.edge.edge_id});
    const firstByTime=[...f.chain.chain.nodes].sort((a,b)=>a.start_time.localeCompare(b.start_time)||a.node_id.localeCompare(b.node_id))[0];
    fireEvent.keyDown(screen.getAllByRole('button',{name:/选择节点/})[0],{key:'Enter'});expect(select).toHaveBeenCalledWith({kind:'node',id:firstByTime.node_id});
  });
  it('retains a backward arrow even when layout time order is forward',() => {
    const e=f.edge.edge;const chain={...f.chain.chain,edges:[{...e,source_node_id:e.target_node_id,target_node_id:e.source_node_id}]};
    const {container}=render(<ChainGraph chain={chain} entities={[]} selection={null} onSelect={vi.fn()}/>);
    expect(container.querySelector('[data-source]')).toHaveAttribute('data-source',e.target_node_id);
  });
  it('renders singleton and permits node selection with zero edges',() => {
    const select=vi.fn();render(<ChainGraph chain={{...f.chain.chain,nodes:[f.chain.chain.nodes[0]],edges:[]}} entities={[]} selection={null} onSelect={select}/>);
    expect(screen.getByText(/未重构出已验证的传播边/)).toBeInTheDocument();expect(screen.queryByRole('button',{name:/选择边/})).not.toBeInTheDocument();fireEvent.click(screen.getByRole('button',{name:/选择节点/}));expect(select).toHaveBeenCalled();
  });
  it('handles empty and partial graphs without constructing edges',() => {
    render(<ChainGraph chain={{...f.chain.chain,nodes:[],edges:[],status:'partial'}} entities={[]} selection={null} onSelect={vi.fn()}/>);
    expect(screen.getByText('当前快照没有可展示节点。')).toBeInTheDocument();expect(screen.getByText(/部分链/)).toBeInTheDocument();
  });
  it('node details expose reasons and every member alert',() => {
    const evidence=vi.fn();render(<NodeDetail node={f.chain.chain.nodes[0]} entities={f.detail.entities} onEvidence={evidence}/>);
    expect(screen.getByText('为什么存在这个节点')).toBeInTheDocument();fireEvent.click(screen.getByRole('button',{name:/查看节点证据/}));expect(evidence.mock.calls[0][0].alertIds).toEqual(f.chain.chain.nodes[0].alert_ids);
  });
  it('edge details expose seven contributions and support_pair evidence',async() => {
    vi.spyOn(api,'edge').mockResolvedValue(f.edge);const evidence=vi.fn();render(<EdgeDetailPanel analysisId={f.analysisId} edge={f.edge.edge} onEvidence={evidence} onNode={vi.fn()}/>);
    await screen.findByText('实际支撑告警对');for(const key of ['time','entity','relation','behavior','source','conflict','duplicate']) expect(screen.getByText(componentLabel(key),{selector:'td'})).toBeInTheDocument();
    fireEvent.click(screen.getByText('查看边证据与字段指针'));expect(evidence.mock.calls[0][0].alertIds).toEqual([f.edge.correlation_edges[0].support_pair.alert_id_src,f.edge.correlation_edges[0].support_pair.alert_id_dst]);
  });
});

describe('Evidence traceability and safe raw display',() => {
  it('loads a single scoped alert and shows real provenance and pointers',async() => {
    vi.spyOn(api,'alert').mockResolvedValue(f.alert);const pointer={alert_id:f.alert.alert.alert_id,pointer:'/rule/id',side:'shared' as const};
    render(<EvidencePanel analysisId={f.analysisId} selection={{title:'节点 Evidence',objectId:'node',alertIds:[f.alert.alert.alert_id],pointers:[pointer]}} onClose={vi.fn()}/>);
    await screen.findByText('相关字段');expect(screen.getByText('绑定证据指针')).toBeInTheDocument();expect(api.alert).toHaveBeenCalledWith(f.analysisId,f.alert.alert.alert_id,expect.any(AbortSignal));
  });
  it('escapes alert HTML and keeps oversized raw text out of DOM until expansion',async() => {
    const raw='<img src=x onerror=alert(1)>'+ 'a'.repeat(5000)+'SECRET_END';
    vi.spyOn(api,'alert').mockResolvedValue({...f.alert,alert:{...f.alert.alert,raw_alert:raw}});
    const {container}=render(<EvidencePanel analysisId={f.analysisId} selection={{title:'Evidence',objectId:'node',alertIds:[f.alert.alert.alert_id]}} onClose={vi.fn()}/>);
    await screen.findByText('相关字段');expect(container.querySelector('img')).toBeNull();expect(container.textContent).not.toContain('SECRET_END');
  });
  it('shows missing evidence as an error',async() => {vi.spyOn(api,'alert').mockRejectedValue(new Error('alert_not_found'));render(<EvidencePanel analysisId={f.analysisId} selection={{title:'Evidence',objectId:'node',alertIds:['missing']}} onClose={vi.fn()}/>);expect(await screen.findByRole('alert')).toHaveTextContent('alert_not_found');});
  it('expands long JSON only on explicit toggle',() => {const {container}=render(<JsonView value={'x'.repeat(5000)+'TAIL_MARKER'}/>);expect(container.textContent).not.toContain('TAIL_MARKER');const details=container.querySelector('details')!;details.open=true;fireEvent(details,new Event('toggle'));expect(container.textContent).toContain('TAIL_MARKER');});
});

describe('Formal AI report and ATT&CK isolation',() => {
  it('uses only verified claims and supports claim → Evidence navigation',() => {
    const report=structuredClone(f.explanation.report_json!);report.claims.push({...report.claims[0],claim_id:'rejected',text:'REJECTED_ATTACK_FACT',grounding_status:'rejected'});report.summary.push({...report.summary[0],claim_id:'rejected',statement:'REJECTED_ATTACK_FACT'});
    const evidence=vi.fn();render(<ReportContent report={report} onEvidence={evidence} onSelect={vi.fn()}/>);expect(screen.queryByText('REJECTED_ATTACK_FACT')).not.toBeInTheDocument();fireEvent.click(screen.getAllByRole('button',{name:/查看陈述证据/})[0]);expect(evidence.mock.calls[0][0].pointers).toEqual(report.summary[0].evidence_refs);
    expect(screen.getByText('建议调查')).toBeInTheDocument();expect(screen.getByText(report.recommended_actions[0].recommendation)).toBeInTheDocument();
  });
  it('renders only validated ATT&CK mappings with a verified mapping claim',() => {
    const report=structuredClone(f.explanation.report_json!);const claim={...report.claims[0],claim_id:'synthetic-map',kind:'attack_mapping' as const,text:'Synthetic accepted mapping'};report.claims.push(claim);
    const technique={claim_id:claim.claim_id,technique_id:'T1059',technique_name:'Command and Scripting Interpreter',tactic:'execution',reason:'Synthetic observed command',catalog_version:'test',mapping_status:'validated',node_refs:[f.chain.chain.nodes[0].node_id],edge_refs:[],alert_refs:[f.alert.alert.alert_id],evidence_refs:report.summary[0].evidence_refs};
    report.attack_techniques=[technique,{...technique,claim_id:'bad',technique_id:'T9999',mapping_status:'rejected'}];const evidence=vi.fn();render(<ReportContent report={report} onEvidence={evidence} onSelect={vi.fn()}/>);expect(screen.getByText(/T1059 ·/)).toBeInTheDocument();expect(screen.queryByText(/T9999/)).not.toBeInTheDocument();const card=screen.getByText(/T1059 ·/).closest('article')!;fireEvent.click(within(card).getByRole('button',{name:/查看陈述证据/}));expect(evidence.mock.calls[0][0].objectId).toBe('synthetic-map');
  });
  it('rejects unvalidated and cross-analysis report envelopes',() => {expect(verifiedReport({...f.explanation,grounding_status:'rejected'},f.analysisId,f.incidentId,f.chain.chain.chain_id)).toBeNull();expect(verifiedReport(f.explanation,'another-analysis',f.incidentId,f.chain.chain.chain_id)).toBeNull();});
  it('reads a persisted report after refresh and separates diagnostics',async() => {
    vi.spyOn(api,'saved').mockResolvedValue(f.saved);render(<AIReport analysisId={f.analysisId} incidentId={f.incidentId} chain={f.chain.chain} onEvidence={vi.fn()} onSelect={vi.fn()} onGenerated={vi.fn()}/>);await screen.findByText('已保存报告');expect(screen.getByText('诊断信息 · 被拒绝内容不属于正式结论')).toBeInTheDocument();expect(screen.getByRole('button',{name:'导出 JSON'})).toBeInTheDocument();
  });
  it('allows singleton explanation and preserves validated deterministic fallback',async() => {
    vi.spyOn(api,'saved').mockResolvedValue({...f.saved,state:'not_generated',result:null,read_origin:null});const result={...f.explanation,status:'unavailable',generation_status:'provider_unavailable',result_origin:'deterministic',degraded:true};vi.spyOn(api,'explain').mockResolvedValue(result);
    render(<AIReport analysisId={f.analysisId} incidentId={f.incidentId} chain={{...f.chain.chain,nodes:[f.chain.chain.nodes[0]],edges:[]}} onEvidence={vi.fn()} onSelect={vi.fn()} onGenerated={vi.fn()}/>);await screen.findByText('尚未生成研判。节点、告警与证据可独立查看。');fireEvent.click(screen.getByText('请求 AI 研判'));await screen.findByText('AI 不可用');expect(screen.getByText(/下方只展示已验证内容/)).toBeInTheDocument();expect(screen.getByText('安全事件摘要')).toBeInTheDocument();
  });
  it('shows partial rejection status without including rejected prose',async() => {
    vi.spyOn(api,'saved').mockResolvedValue({...f.saved,state:'partially_rejected',result:{...f.explanation,generation_status:'partially_rejected',degraded:true,rejected_claims:[{index:1,section:'summary',validation_errors:['unsupported_claim']}]}});render(<AIReport analysisId={f.analysisId} incidentId={f.incidentId} chain={f.chain.chain} onEvidence={vi.fn()} onSelect={vi.fn()} onGenerated={vi.fn()}/>);await screen.findByText('部分拒绝');expect(screen.getByText(/已拒绝 ≠ 已验证/)).toBeInTheDocument();
  });
  it('handles Explain errors without losing the retry button',async() => {
    vi.spyOn(api,'saved').mockResolvedValue({...f.saved,state:'not_generated',result:null});vi.spyOn(api,'explain').mockRejectedValue(new Error('network_unavailable'));render(<AIReport analysisId={f.analysisId} incidentId={f.incidentId} chain={f.chain.chain} onEvidence={vi.fn()} onSelect={vi.fn()} onGenerated={vi.fn()}/>);await screen.findByText('尚未生成研判。节点、告警与证据可独立查看。');fireEvent.click(screen.getByText('请求 AI 研判'));expect(await screen.findByRole('alert')).toHaveTextContent('network_unavailable');expect(screen.getByText('请求 AI 研判')).toBeEnabled();
  });
});

describe('URL scope and stale requests',() => {
  it('aborts the previous scope and ignores its late response',async() => {
    let oldSignal!:AbortSignal, resolveOld!:(value:string)=>void;
    const oldLoad=(signal:AbortSignal)=>{oldSignal=signal;return new Promise<string>(resolve=>{resolveOld=resolve;});};
    const {result,rerender}=renderHook(({scope})=>useResource(scope==='old' ? oldLoad : async()=> 'new snapshot',[scope]),{initialProps:{scope:'old'}});
    rerender({scope:'new'});expect(oldSignal.aborted).toBe(true);
    await waitFor(()=>expect(result.current.data).toBe('new snapshot'));
    await act(async()=>{resolveOld('stale snapshot');});
    expect(result.current.data).toBe('new snapshot');expect(result.current.loading).toBe(false);
  });
  it('loads explicit Analysis and Incident IDs from a refreshed URL',async() => {
    history.replaceState({},'',`/?analysis_id=${f.analysisId}&incident_id=${f.incidentId}`);vi.spyOn(api,'incident').mockResolvedValue(f.detail);vi.spyOn(api,'chain').mockResolvedValue(f.chain);vi.spyOn(api,'observations').mockResolvedValue({analysis_id:f.analysisId,incident_id:f.incidentId,representative_member_count:2,expanded_member_count:2,sources:['wazuh'],fields:[]});vi.spyOn(api,'timeline').mockResolvedValue({items:[],page:1,page_size:20,total:0});vi.spyOn(api,'saved').mockResolvedValue({...f.saved,result:null,state:'not_generated'});render(<App/>);expect(await screen.findByText('关联聚合事件')).toBeInTheDocument();expect(api.incident).toHaveBeenCalledWith(f.analysisId,f.incidentId,expect.any(AbortSignal));
  });
  it('aborts old Incident reads and refuses mixed snapshots',async() => {
    vi.spyOn(api,'incident').mockResolvedValue({...f.detail,analysis_id:'wrong'});vi.spyOn(api,'chain').mockResolvedValue(f.chain);vi.spyOn(api,'observations').mockResolvedValue({analysis_id:f.analysisId,incident_id:f.incidentId,representative_member_count:2,expanded_member_count:2,sources:[],fields:[]});render(<IncidentDetail analysisId={f.analysisId} incidentId={f.incidentId} onEvidence={vi.fn()} onBack={vi.fn()} onGenerated={vi.fn()}/>);expect(await screen.findByRole('alert')).toHaveTextContent('snapshot_scope_mismatch');
  });
});
