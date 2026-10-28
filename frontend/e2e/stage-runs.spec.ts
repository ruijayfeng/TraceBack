/** Real browser + real backend + formal CLI. No API routing or result mocks. */
import {test,expect} from '@playwright/test';
import {mkdir,readFile,writeFile} from 'node:fs/promises';
import path from 'node:path';

const output=path.resolve('../outputs/workbench_productization_checks');

test('overview separates uploaded input from retained alerts after real deduplication',async({page,request})=>{
  const event=JSON.parse((await readFile(path.join(output,'native.jsonl'),'utf8')).trim().split('\n')[0]);
  const duplicate=structuredClone(event);
  duplicate.event.timestamp='2026-01-01T00:00:01+00:00';
  const buffer=Buffer.from([event,duplicate].map(row=>JSON.stringify(row)).join('\n')+'\n');
  await page.goto('/');
  await page.getByRole('button',{name:'导入告警',exact:true}).click();
  const panel=page.getByRole('dialog',{name:'导入告警与分析'});
  await panel.getByLabel('选择告警文件').setInputFiles({name:'deduplicate-count.jsonl',mimeType:'application/octet-stream',buffer});
  await expect(panel.getByText('共 2 条 · 通过 2 条 · 失败 0 条 · 校验通过')).toBeVisible();
  const started=page.waitForResponse(r=>r.request().method()==='POST' && new URL(r.url()).pathname==='/api/v1/stage-runs');
  await panel.getByRole('button',{name:'开始分析',exact:true}).click();
  const task=await started.then(r=>r.json());
  await expect(panel.getByRole('heading',{name:'分析成功',exact:true})).toBeVisible();
  await page.getByRole('button',{name:'关闭导入面板'}).click();
  const metric=page.locator('.overview-metric').filter({has:page.locator('.metric-title',{hasText:/^输入告警$/})}).locator('strong');
  await expect(page.locator('.overview-page')).toHaveAttribute('data-analysis-id',task.run_id);
  await expect(metric).toHaveText('2');
  await expect(page.locator('.trend-meta')).toContainText('共 1 条保留告警');
  const response=await request.get('/api/v1/stage-analyses/'+task.run_id+'/summary');
  expect(response.ok()).toBeTruthy();
  expect((await response.json()).summary.counts).toMatchObject({input_count:2,kept_count:1});
  await page.reload();
  await expect(metric).toHaveText('2');
  await expect(page.locator('.trend-meta')).toContainText('共 1 条保留告警');
  const checks=path.resolve('../outputs/pr_fix_checks');
  await mkdir(checks,{recursive:true});
  await page.screenshot({path:path.join(checks,'deduplicated-overview.png'),fullPage:true});
});

test('uploads two native batches, opens results automatically, switches history and rejects unavailable artifacts',async({page,request})=>{
  const errors:string[]=[];page.on('pageerror',error=>errors.push(error.message));
  const native=await readFile(path.join(output,'native.jsonl'));
  await page.goto('/?view=stages');
  await page.getByRole('button',{name:'导入告警',exact:true}).click();
  const panel=page.getByRole('dialog',{name:'导入告警与分析'});
  const choices=await request.get('/api/v1/stage-analyses').then(r=>r.json());
  const baseline=choices.items.find((item:{official?:boolean})=>item.official);
  expect(baseline).toBeTruthy();
  await page.getByLabel('选择告警文件').setInputFiles({name:'invalid.jsonl',mimeType:'application/octet-stream',buffer:Buffer.from('{}\n')});
  await expect(panel.getByText(/失败 1 条 · 校验失败/)).toBeVisible();
  await expect(panel.getByRole('cell',{name:'source_type',exact:true})).toBeVisible();
  await expect(panel.getByRole('button',{name:'开始分析',exact:true})).toBeDisabled();
  await page.screenshot({path:path.join(output,'ui-validation-errors.png'),fullPage:true});

  const records:any[]=[];
  for(const [name,buffer,count] of [['browser-a.jsonl',native,3],['browser-b.jsonl',Buffer.from(native.toString().trim().split('\n').slice(0,2).join('\n')+'\n'),2]] as const){
    await page.getByLabel('选择告警文件').setInputFiles({name,mimeType:'application/octet-stream',buffer});
    await expect(panel.getByText(new RegExp(`共 ${count} 条 · 通过 ${count} 条 · 失败 0 条 · 校验通过`))).toBeVisible();
    const response=page.waitForResponse(r=>r.request().method()==='POST' && new URL(r.url()).pathname==='/api/v1/stage-runs');
    await panel.getByRole('button',{name:'开始分析',exact:true}).click();
    const started=await response.then(r=>r.json());
    expect(started.status).toBe('QUEUED');
    await expect(panel.locator('.run-details')).toHaveAttribute('data-run-id',started.run_id);
    await expect(panel.locator('.run-details').getByRole('heading',{name:'分析成功',exact:true})).toBeVisible();
    await expect(panel.getByText('产物检查通过，本次分析结果已就绪。')).toBeVisible();
    const record=await request.get('/api/v1/stage-runs/'+started.run_id).then(r=>r.json());
    expect(record.exit_code).toBe(0);expect(record.stages.every((s:{status:string})=>s.status==='COMPLETED')).toBe(true);
    expect(record.recent_log).toContain('@@TRACEBACK_PROGRESS');
    const analysis=await request.get('/api/v1/stage-analyses/'+started.run_id).then(r=>r.json());
    expect(analysis.analysis_id).toBe(started.run_id);expect(analysis.counts.input_count).toBe(count);
    records.push({...record,analysis});
  }
  const [a,b]=records;
  expect(a.run_id).not.toBe(b.run_id);expect(a.output_path).not.toBe(b.output_path);
  await page.getByRole('button',{name:'关闭导入面板'}).click();
  await expect(page.getByRole('heading',{name:'2 条告警分析',exact:true})).toBeVisible();
  await page.screenshot({path:path.join(output,'ui-real-result.png'),fullPage:true});
  for(const record of [a,b,a]){
    await page.getByLabel('历史分析',{exact:true}).selectOption(record.run_id);
    await expect(page.getByRole('heading',{name:`${record.input_count} 条告警分析`,exact:true})).toBeVisible();
    await page.getByRole('button',{name:'导入告警',exact:true}).click();
    await expect(panel.locator('.run-details')).toHaveAttribute('data-run-id',record.run_id);
    await page.getByRole('button',{name:'关闭导入面板'}).click();
    await page.getByRole('button',{name:'阶段列表',exact:true}).click();
    await page.getByRole('button',{name:'查看阶段证据',exact:true}).first().click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.getByRole('dialog').getByRole('button',{name:'查看原始告警',exact:true}).first().click();
    await expect(page.getByRole('dialog').locator('.json-view pre').first()).toBeVisible();
    await page.getByRole('button',{name:'关闭证据',exact:true}).click();
  }
  await page.reload();
  await expect(page.getByLabel('历史分析',{exact:true})).toHaveValue(a.run_id);
  await expect(page.getByRole('heading',{name:'3 条告警分析',exact:true})).toBeVisible();
  await page.getByRole('navigation',{name:'功能模块'}).getByRole('link',{name:'态势总览',exact:true}).click();
  await expect(page.getByRole('heading',{name:'安全运营态势总览',exact:true})).toBeVisible();
  expect(new URL(page.url()).searchParams.get('analysis_id')).toBe(a.run_id);
  await page.getByLabel('历史分析',{exact:true}).selectOption(baseline.analysis_id);
  await expect(page.locator('.overview-metric').first().locator('strong')).toHaveText('125');
  // Mutate only this test's freshly created result; restore it in finally.
  const target=path.join(a.output_path,'stage9.json');
  expect(path.resolve(target)).toBe(path.resolve('../outputs/workbench_runs/runs',a.run_id,'result/stage9.json'));
  const saved=await readFile(target);
  try{
    await writeFile(target,'{}');
    await page.getByLabel('历史分析',{exact:true}).selectOption(a.run_id);
    await expect(page.locator('.run-task-status')).toHaveText('结果不可用');
    if(!await panel.isVisible())await page.locator('.run-task-status').click();
    await expect(panel.getByText(/stage_run_artifacts_invalid/)).toBeVisible();
    await expect(page.locator('.overview-metric')).toHaveCount(0);
    await expect(page.getByRole('heading',{name:'125 条告警分析',exact:true})).toHaveCount(0);
    await expect(page.getByRole('heading',{name:'2 条告警分析',exact:true})).toHaveCount(0);
    await expect(page.getByRole('heading',{name:'3 条告警分析',exact:true})).toHaveCount(0);
    await page.screenshot({path:path.join(output,'ui-unavailable-no-fallback.png'),fullPage:true});
  } finally {await writeFile(target,saved);}
  await page.getByRole('button',{name:'关闭导入面板'}).click();
  await page.getByLabel('历史分析',{exact:true}).selectOption(b.run_id);
  await expect(page.locator('.overview-metric').first().locator('strong')).toHaveText('2');
  await page.setViewportSize({width:390,height:844});
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
  await page.screenshot({path:path.join(output,'ui-mobile.png'),fullPage:true});
  expect(errors).toEqual([]);
  await writeFile(path.join(output,'ui-runs.json'),JSON.stringify(records,null,2));
});

test('displays persisted CLI failure and keeps successful history available',async({page})=>{
  const failed=JSON.parse(await readFile(path.join(output,'ui-failure-run.json'),'utf8'));
  await page.goto('/?view=stages&analysis_id='+failed.run_id);
  await page.getByRole('button',{name:'导入告警',exact:true}).click();
  const panel=page.getByRole('dialog',{name:'导入告警与分析'});
  await expect(panel.getByRole('heading',{name:'分析失败',exact:true})).toBeVisible();
  await expect(panel.getByText(/退出码：7/)).toBeVisible();
  await expect(panel.locator('.run-log')).toContainText('intentional CLI failure for UI diagnostics');
  await expect(page.getByRole('heading',{name:/条告警分析/})).toHaveCount(0);
  await page.screenshot({path:path.join(output,'ui-failed-cli.png'),fullPage:true});
  const [success]=JSON.parse(await readFile(path.join(output,'ui-runs.json'),'utf8'));
  await page.getByRole('button',{name:'关闭导入面板'}).click();
  await page.getByLabel('历史分析',{exact:true}).selectOption(success.run_id);
  await expect(page.getByRole('heading',{name:'3 条告警分析',exact:true})).toBeVisible();
});

test('reopens previously persisted run without re-executing analysis',async({page,request})=>{
  const [,success]=JSON.parse(await readFile(path.join(output,'ui-runs.json'),'utf8'));
  const before=await request.get('/api/v1/stage-runs/'+success.run_id).then(r=>r.json());
  await page.goto('/?view=stages&analysis_id='+success.run_id);
  await expect(page.getByRole('heading',{name:'2 条告警分析',exact:true})).toBeVisible();
  await expect(page.getByLabel('历史分析',{exact:true})).toHaveValue(success.run_id);
  const after=await request.get('/api/v1/stage-runs/'+success.run_id).then(r=>r.json());
  expect(after.started_at).toBe(before.started_at);expect(after.finished_at).toBe(before.finished_at);
  expect(after.artifacts).toEqual(before.artifacts);
});
