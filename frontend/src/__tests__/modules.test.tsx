import {afterEach,describe,expect,it,vi} from 'vitest';
import {cleanup,fireEvent,render,screen,within} from '@testing-library/react';
import App from '../App';
import AnalysisModule from '../pages/AnalysisModule';
import {StageAnalysisView} from '../pages/StageWorkbench';
import {api} from '../api/client';
import type {StageAnalysis} from '../types/stageAnalysis';

const aid='ana_'+'b'.repeat(64);
const stages=Array.from({length:13},(_,i)=>({stage_id:'stage_'+i,community_id:'scene',behavior:i%2?'EXECUTION':'AUTHENTICATION',start_time:'2026-10-22T01:00:00Z',end_time:'2026-10-22T01:01:00Z',alert_ids:['alert_'+i],alert_count:1,source_types:[i%2?'waf':'edr'],evidence_summary:'observed'}));
const chain=(id:string,ids:string[])=>({chain_id:id,stage_ids:ids,relation_ids:[],stage_count:ids.length,relation_count:0,single_stage:ids.length===1,has_directed_cycle:false,entry_stage_ids:[],exit_stage_ids:[]});
const data:StageAnalysis={analysis_id:aid,algorithm_version:'attack-chain-reconstruction-v1',status:'sealed',source_stage:9,counts:{input_count:13,stage_count:13,relation_count:0,chain_count:2,directed_count:0,undirected_count:0},stages,chains:[chain('large',stages.slice(0,12).map(s=>s.stage_id)),chain('small',['stage_12'])],relations:[]};
afterEach(()=>{cleanup();vi.restoreAllMocks();history.replaceState({},'','/');});
function mockAnalysis(){
  vi.spyOn(api,'stageCatalog').mockResolvedValue({default_analysis_id:aid,items:[{analysis_id:aid,input_count:13,algorithm_version:data.algorithm_version}]});
  vi.spyOn(api,'stageAnalysis').mockResolvedValue(data);
  vi.spyOn(api,'stageSummary').mockResolvedValue({analysis_id:aid,summary:{counts:{input_count:13,kept_count:13,stage_count:13,host_count:0},source_type:[],source_namespace:[],source_product:[],hosts:[],behavior:[],time_series:[]}});
}
describe('Module navigation and bounded lists',()=>{
  it('keeps an explicit batch while the catalog is still loading after refresh',async()=>{
    mockAnalysis();vi.mocked(api.stageCatalog).mockImplementation(()=>new Promise(()=>{}));
    history.replaceState({},'','/?view=stages&analysis_id='+aid);render(<App/>);
    await screen.findByRole('heading',{name:'13 条告警分析'});
    fireEvent.click(within(screen.getByRole('navigation',{name:'功能模块'})).getByRole('link',{name:'态势总览'}));
    expect(new URLSearchParams(location.search).get('analysis_id')).toBe(aid);
  });
  it('navigates from home to alerts and back to overview while retaining the analysis scope',async()=>{
    mockAnalysis();render(<App/>);await screen.findByRole('heading',{name:'安全运营态势总览'});
    const nav=screen.getByRole('navigation',{name:'功能模块'});
    fireEvent.click(within(nav).getByRole('link',{name:'安全告警'}));
    await screen.findByRole('heading',{name:'安全告警'});
    expect(new URLSearchParams(location.search).get('analysis_id')).toBe(aid);
    expect(screen.getAllByRole('button',{name:'查看原始告警'})).toHaveLength(10);
    fireEvent.click(within(nav).getByRole('link',{name:'态势总览'}));
    await screen.findByRole('heading',{name:'安全运营态势总览'});
    expect(screen.queryByRole('heading',{name:'13 条告警分析'})).not.toBeInTheDocument();
  });
  it('paginates alerts, resets paging on filtering and fetches raw data only when opened',async()=>{
    const raw=vi.spyOn(api,'stageRaw').mockResolvedValue({raw_alert:{message:'original record'}});
    render(<AnalysisModule view="alerts" data={data} onOpenChain={vi.fn()}/>);
    expect(raw).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button',{name:'下一页'}));
    expect(screen.getAllByRole('button',{name:'查看原始告警'})).toHaveLength(3);
    expect(new URLSearchParams(location.search).get('page')).toBe('2');
    fireEvent.change(screen.getByRole('combobox',{name:'阶段来源'}),{target:{value:'waf'}});
    expect(screen.getAllByRole('button',{name:'查看原始告警'})).toHaveLength(6);
    expect(new URLSearchParams(location.search).has('page')).toBe(false);
    fireEvent.click(screen.getAllByRole('button',{name:'查看原始告警'})[0]);
    await screen.findByText(/original record/);
    expect(raw).toHaveBeenCalledWith(aid,'alert_1',expect.any(AbortSignal));
  });
  it('opens the selected chain from the summary and retains its view on refresh',async()=>{
    mockAnalysis();const app=render(<App/>);await screen.findByRole('heading',{name:'安全运营态势总览'});
    fireEvent.click((await screen.findAllByRole('button',{name:/^查看$/}))[1]);
    await screen.findByRole('heading',{name:'13 条告警分析'});
    expect(new URLSearchParams(location.search).get('chain_id')).toBe('small');
    expect(document.querySelectorAll('.graph-node')).toHaveLength(1);
    fireEvent.click(screen.getByRole('button',{name:'阶段列表'}));
    expect(screen.queryByLabelText('事件完整攻击流程图')).not.toBeInTheDocument();
    expect(new URLSearchParams(location.search).get('panel')).toBe('timeline');
    app.unmount();render(<App/>);
    await screen.findByRole('heading',{name:'阶段时间线'});
    expect(screen.getAllByRole('button',{name:'查看阶段证据'})).toHaveLength(1);
  });
  it('shows one chain view at a time and limits long stage lists to ten rows',()=>{
    render(<StageAnalysisView data={data}/>);
    expect(screen.queryByRole('heading',{name:'阶段时间线'})).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button',{name:'阶段列表'}));
    expect(screen.getAllByRole('button',{name:'查看阶段证据'})).toHaveLength(10);
    fireEvent.click(screen.getByRole('button',{name:'下一页'}));
    expect(screen.getAllByRole('button',{name:'查看阶段证据'})).toHaveLength(2);
    fireEvent.click(screen.getByRole('button',{name:'关系列表'}));
    expect(screen.queryByRole('button',{name:'查看阶段证据'})).not.toBeInTheDocument();
    expect(screen.getByText('该事件没有此类型的关系。')).toBeInTheDocument();
  });
  it('does not render a different analysis returned for a module scope',async()=>{
    mockAnalysis();vi.mocked(api.stageAnalysis).mockResolvedValue({...data,analysis_id:'wrong'});
    history.replaceState({},'','/?view=alerts&analysis_id='+aid);render(<App/>);
    expect(await screen.findByRole('alert')).toHaveTextContent('分析记录不匹配');
    expect(screen.queryByRole('heading',{name:'告警索引'})).not.toBeInTheDocument();
  });
});
