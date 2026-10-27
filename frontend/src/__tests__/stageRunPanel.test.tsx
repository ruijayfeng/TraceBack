import {act,fireEvent,render,screen,within} from '@testing-library/react';
import {afterEach,expect,it,vi} from 'vitest';
import StageRunPanel from '../components/StageRunPanel';
import {api} from '../api/client';
import type {StageRun,StageUpload} from '../types/stageAnalysis';

const id='ana_'+'c'.repeat(64);
const catalog={default_analysis_id:'baseline',items:[{analysis_id:'baseline',input_count:125,algorithm_version:'v1',official:true}]};
const upload:StageUpload={upload_id:'upload',filename:'native.jsonl',size_bytes:256,sha256:'hash',validation:{status:'VALID',total_count:3,valid_count:3,invalid_count:0,errors:[]}};
const queued:StageRun={run_id:id,filename:'native.jsonl',input_count:3,input_sha256:'hash',status:'QUEUED',created_at:'2026-10-27T00:00:00Z',started_at:null,finished_at:null,duration_seconds:null,current_stage:null,failed_stage:null,exit_code:null,failure_reason:null,result_available:false,recent_log:'',stages:[{stage:1,name:'① 告警统一标准化',status:'PENDING'}]};
afterEach(()=>{vi.useRealTimers();localStorage.clear();});

it('keeps the overview compact and preserves validation when the drawer closes',async()=>{
  let uploaded=()=>{};let resolveUpload:(value:StageUpload)=>void=()=>{};
  vi.spyOn(api,'stageUpload').mockImplementation((_file,_signal,onUploaded)=>{uploaded=onUploaded!;return new Promise(resolve=>{resolveUpload=resolve;});});
  render(<StageRunPanel catalog={catalog} selectedId="baseline" view="overview" onSelect={vi.fn()} onRuns={vi.fn()}/>);
  expect(screen.getByRole('heading',{name:'安全运营态势总览'})).toBeInTheDocument();
  expect(screen.queryByLabelText('选择告警文件')).not.toBeInTheDocument();
  expect(screen.queryByRole('region',{name:'历史分析任务'})).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'导入告警'}));
  const dialog=screen.getByRole('dialog',{name:'导入告警与分析'});
  fireEvent.change(within(dialog).getByLabelText('选择告警文件'),{target:{files:[new File(['{}'],'native.jsonl')]}});
  expect(within(dialog).getByText('正在上传文件…')).toBeInTheDocument();
  act(()=>uploaded());expect(within(dialog).getByText('上传完成，正在校验…')).toBeInTheDocument();
  await act(async()=>resolveUpload(upload));
  expect(within(dialog).getByRole('button',{name:'开始分析'})).toBeEnabled();
  fireEvent.click(within(dialog).getByRole('button',{name:'关闭导入面板'}));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'导入告警'}));
  expect(screen.getByText('校验通过，等待开始分析。')).toBeInTheDocument();
});

it('continues polling a submitted task with the drawer closed and selects its actual result',async()=>{
  vi.useFakeTimers();
  vi.spyOn(api,'stageUpload').mockResolvedValue(upload);
  vi.spyOn(api,'stageStart').mockResolvedValue(queued);
  const onSelect=vi.fn();
  render(<StageRunPanel catalog={catalog} selectedId="baseline" view="overview" onSelect={onSelect} onRuns={vi.fn()}/>);
  await act(async()=>{});
  fireEvent.click(screen.getByRole('button',{name:'导入告警'}));
  await act(async()=>{fireEvent.change(screen.getByLabelText('选择告警文件'),{target:{files:[new File(['{}'],'native.jsonl')]}});});
  await act(async()=>{fireEvent.click(screen.getByRole('button',{name:'开始分析'}));});
  expect(screen.getByRole('heading',{name:'分析排队中'})).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'关闭导入面板'}));
  expect(screen.getByRole('button',{name:/分析排队中.*后台运行中/})).toBeInTheDocument();
  expect(onSelect).not.toHaveBeenCalled();
  const done={...queued,status:'SUCCEEDED' as const,result_available:true,exit_code:0,finished_at:'2026-10-27T00:00:01Z',duration_seconds:1};
  vi.mocked(api.stageRuns).mockResolvedValue({items:[done]});
  await act(async()=>{await vi.advanceTimersByTimeAsync(2000);});
  expect(onSelect).toHaveBeenCalledWith(id);
  expect(api.stageStart).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole('button',{name:'导入告警'}));
  expect(screen.getByRole('heading',{name:'分析成功'})).toBeInTheDocument();
});

it('shows the shared history only in records and reopens failure diagnostics',async()=>{
  const failed={...queued,status:'FAILED' as const,exit_code:7,failure_reason:'real CLI exit 7',recent_log:'diagnostic stderr',failed_stage:'① 告警统一标准化'};
  vi.mocked(api.stageRuns).mockResolvedValue({items:[failed]});
  render(<StageRunPanel catalog={catalog} selectedId="baseline" view="records" onSelect={vi.fn()} onRuns={vi.fn()}/>);
  fireEvent.click(await screen.findByRole('button',{name:'查看状态与日志'}));
  expect(screen.getByRole('heading',{name:'分析失败'})).toBeInTheDocument();
  expect(screen.getByText(/real CLI exit 7/)).toBeInTheDocument();
  expect(screen.getByText('diagnostic stderr')).toBeInTheDocument();
  fireEvent.click(screen.getByRole('button',{name:'关闭导入面板'}));
  fireEvent.click(screen.getByRole('button',{name:'查看状态与日志'}));
  expect(screen.getByText('diagnostic stderr')).toBeInTheDocument();
});

it('restores the selected task when opened before history finishes loading',async()=>{
  let resolveHistory:(value:{items:StageRun[]})=>void=()=>{};
  vi.mocked(api.stageRuns).mockImplementation(()=>new Promise(resolve=>{resolveHistory=resolve;}));
  render(<StageRunPanel catalog={null} selectedId={id} view="overview" onSelect={vi.fn()} onRuns={vi.fn()}/>);
  fireEvent.click(screen.getByRole('button',{name:'导入告警'}));
  await act(async()=>resolveHistory({items:[{...queued,status:'FAILED',failure_reason:'persisted CLI failure',recent_log:'retained failure log'}]}));
  expect(screen.getByRole('heading',{name:'分析失败'})).toBeInTheDocument();
  expect(screen.getByText('retained failure log')).toBeInTheDocument();
});
