import {originLabel, severityLabel, statusLabel, entityLabel} from '../../lib/displayLabels';
import {FileJson, FileText, RefreshCw, Sparkles, StopCircle} from 'lucide-react';
import {lazy, Suspense, useEffect, useRef, useState} from 'react';
import {api} from '../../api/client';
import type {AIState, Chain, EvidenceSelection, Explanation, Finding, Report, Technique} from '../../types/domain';
import {AIStatus, JsonView, Notice, Section, StableId} from '../common';
// rare-ui ai-status pulls in Motion; load it only while a generation is in flight.
const AiStatus = lazy(() => import('../ui/ai-status'));
import {Dialog, DialogClose, DialogDescription, DialogFooter, DialogHeader, DialogPopup, DialogTitle} from '../ui/dialog';
import {EmptyState} from '../ui/empty-state';
import {ErrorState} from '../ui/error-state';
import {TextSkeleton} from '../ui/skeleton';
import {TraceIcon} from '../ui/trace-icon';
import {notify} from '../ui/toast';

export function verifiedReport(result: Explanation | null, analysisId: string, incidentId: string, chainId: string): Report | null {
  const report = result?.report_json;
  if (!result || !report || result.analysis_id !== analysisId || result.incident_id !== incidentId || result.grounding_status !== 'validated' ||
    report.analysis_id !== analysisId || report.incident_id !== incidentId || report.chain_id !== chainId || report.grounding_status !== 'validated') return null;
  return report;
}

function ClaimText({text}: {text: string}) {
  const [expanded, setExpanded] = useState(false);
  const long = text.length > 280;
  return <><p className={long && !expanded ? 'claim-text clamped' : 'claim-text'}>{text}</p>{long && <button className="text-button claim-toggle" onClick={() => setExpanded(value => !value)} type="button">{expanded ? '收起全文' : `展开全文（${text.length.toLocaleString()} 字符）`}</button>}</>;
}

function EvidenceLinks({finding, onEvidence, onSelect}: {finding: Finding; onEvidence: (e: EvidenceSelection) => void; onSelect: (kind: 'node' | 'edge', id: string) => void}) {
  const references = finding.evidence_refs.length + finding.alert_refs.length;
  return <div className="claim-links">
    <button disabled={references === 0} onClick={() => onEvidence({title: '已验证陈述证据', objectId: finding.claim_id, alertIds: finding.alert_refs, pointers: finding.evidence_refs})} title={references === 0 ? '该陈述没有可定位的证据引用' : '打开绑定证据'} type="button">查看陈述证据 · {references} 引用</button>
    {finding.node_refs.map(n => <button key={n} onClick={() => onSelect('node', n)} type="button">节点 <StableId copy={false} label="节点 ID" value={n}/></button>)}
    {finding.edge_refs.map(e => <button key={e} onClick={() => onSelect('edge', e)} type="button">边 <StableId copy={false} label="边 ID" value={e}/></button>)}
  </div>;
}

export function ReportContent({report, onEvidence, onSelect}: {report: Report; onEvidence: (e: EvidenceSelection) => void; onSelect: (kind: 'node' | 'edge', id: string) => void}) {
  const claims = new Map(report.claims.filter(c => c.grounding_status === 'validated').map(c => [c.claim_id, c]));
  const findings = (items: Finding[]) => items.filter(f => claims.has(f.claim_id)).map(f => <article className="finding" key={f.claim_id}><span className="badge verified">已验证 · {claims.get(f.claim_id)!.kind === 'inference' ? 'AI 解释 / 推测' : '有据事实'}</span><ClaimText text={claims.get(f.claim_id)!.text}/><EvidenceLinks finding={f} onEvidence={onEvidence} onSelect={onSelect}/></article>);
  const attackPath = report.attack_path.filter(f => claims.has(f.claim_id)).map(f => <article className="finding attack-step" key={f.claim_id}><div className="attack-step-heading"><span className="step-index">步骤 {f.step}</span><span className="badge verified">已验证 · {claims.get(f.claim_id)!.kind === 'inference' ? 'AI 解释 / 推测' : '有据事实'}</span></div><ClaimText text={claims.get(f.claim_id)!.text}/><EvidenceLinks finding={f} onEvidence={onEvidence} onSelect={onSelect}/></article>);
  const techniques = report.attack_techniques.filter(t => t.mapping_status === 'validated' && claims.get(t.claim_id)?.kind === 'attack_mapping');
  const recommendationClaims = [...claims.values()].filter(c => c.kind === 'recommendation');
  const actions = report.recommended_actions.filter(a => recommendationClaims.some(c => c.text.includes(a.recommendation)));
  const reportSections = [['report-summary','摘要'],['report-findings','发现'],['report-attack-path','攻击过程'],['report-attack','ATT&CK'],['report-entities','实体'],['report-risk','风险'],['report-actions','建议']] as const;
  return <><nav aria-label="报告导航" className="report-nav">{reportSections.map(([id,label]) => <a className="report-nav-link" href={'#'+id} key={id}>{label}</a>)}</nav>
    <Section id="report-summary" title="安全事件摘要" hint={report.result_origin === 'deterministic' ? '确定性事实模板 · AI 未生成' : '已通过证据锚定校验'}>{findings(report.summary)}</Section>
    <Section id="report-findings" title="关键发现">{findings(report.observed_facts)}</Section>
    <Section id="report-attack-path" title="攻击过程">{report.has_directed_path ? (attackPath.length ? attackPath : <Notice>当前没有已验证的多阶段有向路径。</Notice>) : <Notice>当前没有已验证的多阶段有向路径。</Notice>}</Section>
    <Section id="report-attack" title="ATT&CK · 已验证映射" hint="语义解释 · 不补充攻击步骤">{techniques.length ? techniques.map(t => <TechniqueCard key={t.claim_id} technique={t} text={claims.get(t.claim_id)!.text} onEvidence={onEvidence} onSelect={onSelect}/>) : <><Notice>没有通过本地目录校验的 ATT&CK 技术。</Notice>{report.attack_techniques.length > 0 && <p className="muted">另有 {report.attack_techniques.length} 条映射未通过本地目录校验，已隔离在诊断信息中。</p>}</>}</Section>
    <Section id="report-entities" title="关键实体">{report.key_entities.length ? report.key_entities.map(e => <div className="entity-row" key={e.entity_id}><b>{entityLabel(e.type)}</b><span>{e.value}</span><button onClick={() => onEvidence({title: '实体证据', objectId: e.entity_id, alertIds: [...new Set(e.evidence_refs.map(p => p.alert_id))].sort(), pointers: e.evidence_refs})} type="button">证据</button></div>) : <Notice>报告中没有关键实体。</Notice>}</Section>
    <Section id="report-risk" title="风险与不确定性"><p>{report.risk.statement}</p><p className="muted">设备观测等级：{severityLabel(report.risk.observed_severity)}</p><ul>{report.limitations.map(u => <li key={u.code}>{u.statement}</li>)}</ul></Section>
    <Section id="report-actions" title="建议调查" hint="建议动作 · 尚未执行">{actions.length ? <ol className="actions">{actions.map(a => <li key={a.action}><b>{a.recommendation}</b><p className="muted">{a.reason}</p>{a.related_object_refs.length > 0 && <small>{a.related_object_refs.map(r => <StableId copy={false} key={r} label="关联对象 ID" value={r}/>)}</small>}</li>)}</ol> : <Notice>没有已验证的调查建议。</Notice>}</Section>
  </>;
}

function TechniqueCard({technique: t, text, onEvidence, onSelect}: {technique: Technique; text: string; onEvidence: (e: EvidenceSelection) => void; onSelect: (kind: 'node' | 'edge', id: string) => void}) {
  return <article className="technique"><span className="badge verified">目录已验证</span><h3>{t.technique_id} · {t.technique_name}</h3><p>{t.tactic} · 目录版本 {t.catalog_version}</p><p>{t.reason}</p><details><summary>支撑陈述</summary><p>{text}</p><StableId label="陈述 ID" value={t.claim_id}/></details><EvidenceLinks finding={{...t, statement: text}} onEvidence={onEvidence} onSelect={onSelect}/></article>;
}

const GENERATION_TIMEOUT_MS = 45_000;
const NO_ALERT_STATE: AIState = 'not_generated';

export function AIReport({analysisId, incidentId, chain, onEvidence, onSelect, onGenerated}: {analysisId: string; incidentId: string; chain: Chain; onEvidence: (e: EvidenceSelection) => void; onSelect: (kind: 'node' | 'edge', id: string) => void; onGenerated: () => void}) {
  const [result, setResult] = useState<Explanation | null>(null);
  const [state, setState] = useState<AIState>(NO_ALERT_STATE);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [cancelled, setCancelled] = useState(false);
  const controller = useRef<AbortController | null>(null);
  const manualAbort = useRef(false);
  const timeoutRef = useRef<number | undefined>(undefined);
  const jobIdRef = useRef<string | null>(null);
  function loadSaved(c: AbortController) {
    setResult(null); setState(NO_ALERT_STATE); setError(null); setLoading(true); setSaved(false); setCancelled(false);
    api.saved(analysisId, incidentId, c.signal).then(data => {if (!c.signal.aborted) {setResult(data.result); setState(data.state); setSaved(data.read_origin === 'persisted'); setLoading(false);}})
      .catch(e => {if (!c.signal.aborted) {setError(e.message); setLoading(false);}});
  }
  useEffect(() => {
    const c = new AbortController(); controller.current = c;
    loadSaved(c);
    return () => {c.abort();controller.current?.abort();window.clearTimeout(timeoutRef.current);};
  }, [analysisId, incidentId]);
  useEffect(() => {
    if (state !== 'generating') {setElapsed(0);return;}
    const started = Date.now();
    const timer = window.setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000);
    return () => window.clearInterval(timer);
  }, [state]);
  function retrySaved() {
    controller.current?.abort(); const c = new AbortController(); controller.current = c; loadSaved(c);
  }
  function requestGenerate() {
    if (result && saved) {setConfirmOpen(true);return;}
    void generate();
  }
  function cancelGenerate() {
    manualAbort.current = true;
    controller.current?.abort();
    window.clearTimeout(timeoutRef.current);
    if (jobIdRef.current) void api.cancelExplainJob(jobIdRef.current).catch(() => undefined);
    setCancelled(true);
    setState('failed');
    setError('ai_generation_cancelled');
    notify.info('已取消本次生成');
  }
  async function generate() {
    controller.current?.abort(); const c = new AbortController(); controller.current = c;
    manualAbort.current = false;
    jobIdRef.current = null;
    setState('generating'); setError(null); setSaved(false); setCancelled(false);
    timeoutRef.current = window.setTimeout(() => {
      manualAbort.current = true;
      c.abort();
      if (jobIdRef.current) void api.cancelExplainJob(jobIdRef.current).catch(() => undefined);
      setState('failed');
      setError('ai_generation_timeout');
    }, GENERATION_TIMEOUT_MS);
    try {
      // T103: async job + polling, so slow providers can be cancelled/observed.
      const started = await api.startExplainJob(analysisId, incidentId, c.signal);
      if (c.signal.aborted) return;
      jobIdRef.current = started.job_id;
      const startedAt = Date.now();
      let value: Explanation | null = null;
      while (!c.signal.aborted) {
        await new Promise(resolve => window.setTimeout(resolve, 600));
        if (c.signal.aborted) return;
        const job = await api.explainJob(started.job_id, c.signal);
        if (job.status === 'queued' || job.status === 'running') continue;
        if (job.status === 'cancelled') {
          if (!manualAbort.current) { setState('failed'); setError('ai_generation_cancelled'); }
          return;
        }
        if (job.status === 'failed') throw new Error(job.error ?? 'request_failed');
        value = job.result ?? null;
        // Keep the progress surface visible for at least ~1s to avoid a flash.
        if (Date.now() - startedAt < 900) await new Promise(resolve => window.setTimeout(resolve, 900 - (Date.now() - startedAt)));
        break;
      }
      window.clearTimeout(timeoutRef.current);
      if (!value) {
        if (!c.signal.aborted && !manualAbort.current) { setState('failed'); setError('invalid_response'); }
        return;
      }
      setResult(value); setState(value.generation_status === 'partially_rejected' ? 'partially_rejected' : value.status === 'available' ? 'completed' : value.status === 'unavailable' ? 'unavailable' : 'failed'); onGenerated(); if (value.degraded) notify.info('研判完成，但部分内容未通过校验'); else notify.success('研判结果已更新');
    } catch (e) {
      window.clearTimeout(timeoutRef.current);
      if (manualAbort.current) return;
      if (c.signal.aborted) return;
      setState('failed'); setError((e as Error).message); notify.error('研判请求未完成，可重试');
    }
  }
  const report = verifiedReport(result, analysisId, incidentId, chain.chain_id);
  // Prefetch the lazy animated status chunk so the first generating state does
  // not flash a fallback while Motion loads.
  useEffect(() => {
    if (!result) void import('../ui/ai-status');
  }, [result]);
  function download(kind: 'json' | 'md') {
    if (!report || !result) return;
    try {
      const url = URL.createObjectURL(new Blob([kind === 'json' ? JSON.stringify(report, null, 2) : result.report_markdown ?? ''], {type: kind === 'json' ? 'application/json' : 'text/markdown'}));
      const link = document.createElement('a'); link.href = url; link.download = `${incidentId}.${kind}`; link.click(); URL.revokeObjectURL(url); notify.success(kind === 'json' ? 'JSON 已导出' : 'Markdown 已导出');
    } catch {notify.error('导出失败，请重试');}
  }
  const generating = state === 'generating';
  return <div className="ai-area" id="ai-report"><Section title="AI 研判报告" hint="解释已有结果">
    <div className="ai-toolbar"><AIStatus state={state}/>{saved && <span className="badge">已保存报告</span>}
      <button className="primary" disabled={generating || loading} onClick={requestGenerate} type="button"><TraceIcon icon={generating ? RefreshCw : Sparkles} size={14}/>{generating ? '正在生成…' : result ? '重新请求 AI 研判' : '请求 AI 研判'}</button>
      {generating && <button onClick={cancelGenerate} type="button"><TraceIcon icon={StopCircle} size={14}/>取消生成</button>}
      {report && <><button onClick={() => download('json')} type="button"><TraceIcon icon={FileJson} size={14}/>导出 JSON</button><button onClick={() => download('md')} type="button"><TraceIcon icon={FileText} size={14}/>导出 Markdown</button></>}
    </div>
    {generating && <div className="ai-generating-row"><Suspense fallback={<span className="muted">正在生成…</span>}><AiStatus className="ai-status-inline" detail={`${GENERATION_TIMEOUT_MS / 1000}s 超时`} elapsed={elapsed} label="正在生成…" state="thinking" /></Suspense><span className="muted">已等待 {elapsed} 秒；可取消，超时会保留上次报告。</span></div>}
    {loading && <TextSkeleton lines={3}/>}
    {loading && <Notice kind="loading">正在读取已保存的正式报告…</Notice>}
    {error && <ErrorState error={error} onRetry={state === 'failed' ? requestGenerate : retrySaved} scope="AI 研判报告"/>}
    {cancelled && <Notice kind="info">已取消生成。上次已验证的报告和证据仍保留。</Notice>}
    {!loading && !result && !error && <EmptyState description="节点、告警与证据仍可独立查看；生成后会保存正式报告。" title="尚未生成研判。节点、告警与证据可独立查看。"/>}
    {result && <p className="muted">生成状态：{statusLabel(result.generation_status)} · 来源：{originLabel(result.result_origin)}{result.provider_metadata && ` · ${result.provider_metadata.provider} / ${result.provider_metadata.model}`}</p>}
    {result?.degraded && <Notice kind="info">AI 不可用或部分生成内容被拒绝。下方只展示已验证内容；确定性事实模板不代表模型生成成功。</Notice>}
    {result && !report && <Notice kind="error">报告未通过发布或快照一致性检查，不能作为正式结论展示。</Notice>}
    <Dialog onOpenChange={setConfirmOpen} open={confirmOpen}>
      <DialogPopup aria-label="重新生成 AI 研判">
        <DialogHeader><DialogTitle>重新生成会覆盖已保存报告</DialogTitle><DialogDescription>将再次请求 AI 研判并覆盖当前已保存的正式报告。设备告警、攻击链与证据不会被修改。</DialogDescription></DialogHeader>
        <DialogFooter><DialogClose type="button">取消</DialogClose><button className="primary" onClick={() => {setConfirmOpen(false);void generate();}} type="button">确认重新生成</button></DialogFooter>
      </DialogPopup>
    </Dialog>
  </Section>
    {report && <ReportContent report={report} onEvidence={onEvidence} onSelect={onSelect}/>}
    {result && <details className="diagnostics"><summary>诊断信息 · 被拒绝内容不属于正式结论</summary><p>已拒绝 ≠ 已验证。这里只显示验证错误码，不发布被拒绝的原始文本。</p><JsonView value={{rejected_claims: result.rejected_claims, rejected_mappings: result.rejected_mappings, validation_errors: result.validation_errors}}/></details>}
    {report && result?.report_markdown && <details className="raw-report"><summary>原始报告 / Markdown</summary><pre className="markdown-preview">{result.report_markdown}</pre></details>}
  </div>;
}
