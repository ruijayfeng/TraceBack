import {originLabel, severityLabel, statusLabel, entityLabel} from '../../lib/displayLabels';
import {useEffect, useRef, useState} from 'react';
import {api} from '../../api/client';
import type {AIState, Chain, EvidenceSelection, Explanation, Finding, Report, Technique} from '../../types/domain';
import {AIStatus, JsonView, Notice, Section, StableId} from '../common';

export function verifiedReport(result: Explanation | null, analysisId: string, incidentId: string, chainId: string): Report | null {
  const report = result?.report_json;
  if (!result || !report || result.analysis_id !== analysisId || result.incident_id !== incidentId || result.grounding_status !== 'validated' ||
    report.analysis_id !== analysisId || report.incident_id !== incidentId || report.chain_id !== chainId || report.grounding_status !== 'validated') return null;
  return report;
}
export function ReportContent({report, onEvidence, onSelect}: {report: Report; onEvidence: (e: EvidenceSelection) => void; onSelect: (kind: 'node' | 'edge', id: string) => void}) {
  const claims = new Map(report.claims.filter(c => c.grounding_status === 'validated').map(c => [c.claim_id, c]));
  const findings = (items: Finding[]) => items.filter(f => claims.has(f.claim_id)).map(f => <article className="finding" key={f.claim_id}><span className="badge verified">已验证 · {claims.get(f.claim_id)!.kind === 'inference' ? 'AI 解释 / 推测' : '有据事实'}</span><p>{claims.get(f.claim_id)!.text}</p><EvidenceLinks finding={f} onEvidence={onEvidence} onSelect={onSelect}/></article>);
  const techniques = report.attack_techniques.filter(t => t.mapping_status === 'validated' && claims.get(t.claim_id)?.kind === 'attack_mapping');
  const actions = report.recommended_actions.filter(a => [...claims.values()].some(c => c.kind === 'recommendation' && (c.text === a.recommendation || c.text === `${a.recommendation} ${a.reason}`)));
  return <><Section title="安全事件摘要" hint={report.result_origin === 'deterministic' ? '确定性事实模板 · AI 未生成' : '已通过证据锚定校验'}>{findings(report.summary)}</Section>
    <Section title="关键发现">{findings(report.observed_facts)}</Section>
    <Section title="攻击过程">{report.has_directed_path ? findings(report.attack_path) : <Notice>当前没有已验证的多阶段有向路径。</Notice>}</Section>
    <Section title="ATT&CK · 已验证映射" hint="语义解释 · 不补充攻击步骤">{techniques.length ? techniques.map(t => <TechniqueCard key={t.claim_id} technique={t} text={claims.get(t.claim_id)!.text} onEvidence={onEvidence} onSelect={onSelect}/>) : <Notice>没有通过本地目录校验的 ATT&CK 技术。</Notice>}</Section>
    <Section title="关键实体">{report.key_entities.length ? report.key_entities.map(e => <div className="entity-row" key={e.entity_id}><b>{entityLabel(e.type)}</b><span>{e.value}</span><button onClick={() => onEvidence({title: '实体证据', objectId: e.entity_id, alertIds: [...new Set(e.evidence_refs.map(p => p.alert_id))].sort(), pointers: e.evidence_refs})}>证据</button></div>) : <Notice>报告中没有关键实体。</Notice>}</Section>
    <Section title="风险与不确定性"><p>{report.risk.statement}</p><p className="muted">设备观测等级：{severityLabel(report.risk.observed_severity)}</p><ul>{report.limitations.map(u => <li key={u.code}>{u.statement}</li>)}</ul></Section>
    <Section title="建议调查" hint="建议动作 · 尚未执行">{actions.length ? <ol className="actions">{actions.map(a => <li key={a.action}><b>{a.recommendation}</b><p className="muted">{a.reason}</p>{a.related_object_refs.length > 0 && <small>{a.related_object_refs.map(r => <StableId key={r} value={r}/>)}</small>}</li>)}</ol> : <Notice>没有已验证的调查建议。</Notice>}</Section>
  </>;
}
function EvidenceLinks({finding, onEvidence, onSelect}: {finding: Finding; onEvidence: (e: EvidenceSelection) => void; onSelect: (kind: 'node' | 'edge', id: string) => void}) {
  return <div className="claim-links"><button onClick={() => onEvidence({title: '已验证陈述证据', objectId: finding.claim_id, alertIds: finding.alert_refs, pointers: finding.evidence_refs})}>查看陈述证据 · {finding.evidence_refs.length} 引用</button>{finding.node_refs.map(n => <button key={n} onClick={() => onSelect('node', n)}>节点 <StableId value={n}/></button>)}{finding.edge_refs.map(e => <button key={e} onClick={() => onSelect('edge', e)}>边 <StableId value={e}/></button>)}</div>;
}
function TechniqueCard({technique: t, text, onEvidence, onSelect}: {technique: Technique; text: string; onEvidence: (e: EvidenceSelection) => void; onSelect: (kind: 'node' | 'edge', id: string) => void}) {
  return <article className="technique"><span className="badge verified">目录已验证</span><h3>{t.technique_id} · {t.technique_name}</h3><p>{t.tactic} · 目录版本 {t.catalog_version}</p><p>{t.reason}</p><details><summary>支撑陈述</summary><p>{text}</p><StableId value={t.claim_id}/></details><EvidenceLinks finding={{...t, statement: text}} onEvidence={onEvidence} onSelect={onSelect}/></article>;
}

export function AIReport({analysisId, incidentId, chain, onEvidence, onSelect, onGenerated}: {analysisId: string; incidentId: string; chain: Chain; onEvidence: (e: EvidenceSelection) => void; onSelect: (kind: 'node' | 'edge', id: string) => void; onGenerated: () => void}) {
  const [result, setResult] = useState<Explanation | null>(null);
  const [state, setState] = useState<AIState>('not_generated');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const controller = useRef<AbortController | null>(null);
  useEffect(() => {
    const c = new AbortController(); controller.current = c;
    setResult(null); setState('not_generated'); setError(null); setLoading(true); setSaved(false);
    api.saved(analysisId, incidentId, c.signal).then(data => {if (!c.signal.aborted) {setResult(data.result); setState(data.state); setSaved(data.read_origin === 'persisted'); setLoading(false);}})
      .catch(e => {if (!c.signal.aborted) {setError(e.message); setLoading(false);}});
    return () => {c.abort();controller.current?.abort();};
  }, [analysisId, incidentId]);
  async function generate() {
    controller.current?.abort(); const c = new AbortController(); controller.current = c;
    setState('generating'); setError(null); setSaved(false);
    try {
      const value = await api.explain(analysisId, incidentId, c.signal);
      if (c.signal.aborted) return;
      setResult(value); setState(value.generation_status === 'partially_rejected' ? 'partially_rejected' : value.status === 'available' ? 'completed' : value.status === 'unavailable' ? 'unavailable' : 'failed'); onGenerated();
    } catch (e) {if (!c.signal.aborted) {setState('failed'); setError((e as Error).message);}}
  }
  const report = verifiedReport(result, analysisId, incidentId, chain.chain_id);
  function download(kind: 'json' | 'md') {
    if (!report || !result) return;
    const url = URL.createObjectURL(new Blob([kind === 'json' ? JSON.stringify(report, null, 2) : result.report_markdown ?? ''], {type: kind === 'json' ? 'application/json' : 'text/markdown'}));
    const link = document.createElement('a'); link.href = url; link.download = `${incidentId}.${kind}`; link.click(); URL.revokeObjectURL(url);
  }
  return <div className="ai-area"><Section title="AI 研判报告" hint="解释已有结果"><div className="ai-toolbar"><AIStatus state={state}/>{saved && <span className="badge">已保存报告</span>}<button className="primary" disabled={state === 'generating' || loading} onClick={generate}>{state === 'generating' ? '正在生成…' : result ? '重新请求 AI 研判' : '请求 AI 研判'}</button>{report && <><button onClick={() => download('json')}>导出 JSON</button><button onClick={() => download('md')}>导出 Markdown</button></>}</div>
    {loading && <Notice kind="loading">正在读取已保存的正式报告…</Notice>}{error && <Notice kind="error">研判请求不可用：{error}</Notice>}
    {!loading && !result && !error && <Notice>尚未生成研判。节点、告警与证据可独立查看。</Notice>}
    {result && <p className="muted">生成状态：{statusLabel(result.generation_status)} · 来源：{originLabel(result.result_origin)}{result.provider_metadata && ` · ${result.provider_metadata.provider} / ${result.provider_metadata.model}`}</p>}
    {result?.degraded && <Notice kind="info">AI 不可用或部分生成内容被拒绝。下方只展示已验证内容；确定性事实模板不代表模型生成成功。</Notice>}
    {result && !report && <Notice kind="error">报告未通过发布或快照一致性检查，不能作为正式结论展示。</Notice>}</Section>
    {report && <ReportContent report={report} onEvidence={onEvidence} onSelect={onSelect}/>}
    {result && <details className="diagnostics"><summary>诊断信息 · 被拒绝内容不属于正式结论</summary><p>已拒绝 ≠ 已验证。这里只显示验证错误码，不发布被拒绝的原始文本。</p><JsonView value={{rejected_claims: result.rejected_claims, rejected_mappings: result.rejected_mappings, validation_errors: result.validation_errors}}/></details>}
    {report && result?.report_markdown && <details className="raw-report"><summary>原始报告 / Markdown</summary><JsonView value={result.report_markdown}/></details>}
  </div>;
}
