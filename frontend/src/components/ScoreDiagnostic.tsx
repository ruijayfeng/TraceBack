import {Section, Notice} from './common';
import {Fragment} from 'react';
import {componentLabel,scoreComponents} from '../lib/displayLabels';
import type {ScoreDiagnosticData} from '../types/domain';
import {Card} from './ui/card';

export function ScoreDiagnostic({data}: {data?: ScoreDiagnosticData}) {
  const score = (v: number | null | undefined) => v == null ? '未提供' : v.toFixed(6).replace(/0+$/,'').replace(/\.$/,'');
  const top = data?.top_candidates?.[0];
  if (!data || data.status !== 'available') {
    return <Card className="diag-compact">
      <details>
        <summary>关联评分诊断 · 未生成</summary>
        <div className="diag-body">
          <p>{data?.conclusion ?? '此冻结快照尚未生成关联评分诊断。'}</p>
          <p>诊断缺失只影响评分配置复核，不影响事件、攻击链与证据的查看。</p>
        </div>
      </details>
    </Card>;
  }
  return <Section actions={null} hint="只读诊断 · 不改变正式关联结果" title="关联评分诊断">
    <dl className="facts">
      <div className="fact"><dt>关联阈值</dt><dd>{score(data.threshold)}</dd></div>
      <div className="fact"><dt>配置理论上限</dt><dd>{score(data.theoretical_config_max)}</dd></div>
      <div className="fact"><dt>真实最高分</dt><dd>{score(data.observed_max)}</dd></div>
      <div className="fact"><dt>数据集可达最高分</dt><dd>{score(data.dataset_reachable_max)}</dd></div>
      <div className="fact"><dt>距离阈值</dt><dd>{score(data.threshold_gap)}</dd></div>
      <div className="fact"><dt>已评分候选</dt><dd>{data.scored_candidate_count?.toLocaleString()}</dd></div>
      <div className="fact"><dt>通过阈值候选</dt><dd>{data.passed_threshold_count?.toLocaleString()}</dd></div>
    </dl>
    <p className="score-conclusion">{data.conclusion}</p>
    <details className="subtle-details">
      <summary>最高分候选评分构成与未获得证据</summary>
      <div className="score-details"><div><h3>最高分候选评分构成</h3>{top && <dl className="facts score-breakdown">{scoreComponents.filter(key=>key in top.contributions).map(key => <Fragment key={key}><dt>{componentLabel(key)}</dt><dd>{top.contributions[key] >= 0 ? '+' : ''}{score(top.contributions[key])}</dd></Fragment>)}<dt>总分</dt><dd><strong>{score(top.score)}</strong></dd></dl>}</div>
        <div><h3>未获得的关键证据</h3><ul>{data.missing_evidence?.map(v => <li key={v}>{v}</li>)}</ul><p>限制层：{data.root_cause_label ?? data.root_cause_classification}</p></div></div>
    </details>
    {data.candidate_generation_check?.bottleneck === 'NO' && data.passed_threshold_count === 0 && <Notice kind="info">当前 0 条关联边是严格证据准入结果。已核验候选剪枝不会遗漏可达阈值的组合。</Notice>}
    <details className="subtle-details"><summary>反事实证据说明（未观测，不加入事实）</summary><p>{data.counterfactual?.summary}</p></details>
  </Section>;
}
