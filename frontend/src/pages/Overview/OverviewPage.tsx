import {useState} from 'react';
import {Icon, type IconName} from '../../components/Icon';
import {Notice, StableId} from '../../components/common';
import {sourceLabel, behaviorName} from '../../lib/displayLabels';
import type {StageAnalysis, StageSummary, StageChain, Stage} from '../../types/stageAnalysis';
import '../../styles/overview.css';

// Six source namespaces observed in the sealed ATTACK125 run, mapped to the
// six device classes TraceBack normalises. Display only; never rewrites data.
const sourceNamespaceLabel = (v: string) => {
  const m: Record<string, string> = {
    'traceback.lab.edr': 'EDR', 'traceback.lab.waf': 'WAF', 'traceback.lab.ids': 'IDS',
    'traceback.lab.firewall': '防火墙', 'traceback.lab.authentication': '认证',
    'traceback.lab.host_audit': '主机审计',
  };
  return m[v] ?? v.replace('traceback.lab.', '');
};

// Sort chains for overview: multi-stage first, then by relation count, then id.
function sortChains(chains: StageChain[]) {
  return [...chains].sort((a, b) =>
    (b.stage_count - a.stage_count) || (b.relation_count - a.relation_count) ||
    (b.directed_count ?? 0) - (a.directed_count ?? 0) || a.chain_id.localeCompare(b.chain_id));
}

// -- Metric cards ---------------------------------------------------------
function MetricCards({data}: {data: StageAnalysis}) {
  const c = data.counts;
  const cards: {title: string; value: number; hint: string}[] = [
    {title: '输入告警', value: c.input_count, hint: '多源设备原始告警'},
    {title: '攻击阶段', value: c.stage_count, hint: '行为语义聚合'},
    {title: '已接受关系', value: c.relation_count, hint: '证据判定通过'},
    {title: '攻击链结构', value: c.chain_count, hint: '连通分量重构'},
    {title: 'Community', value: c.community_count ?? new Set(data.stages.map(s=>s.community_id)).size, hint: '告警调查分组'},
    {title: 'Stage Pair', value: c.decision_count ?? 0, hint: '正式候选阶段对'},
    {title: '主体攻击链', value: data.chains.filter(c=>!c.single_stage).length, hint: '多阶段链结构'},
    {title: '孤立阶段', value: data.chains.filter(c=>c.single_stage).length, hint: '单阶段链结构'},
    {title: '有向关系', value: c.directed_count ?? 0, hint: '证据语义方向'},
    {title: '无向关系', value: c.undirected_count ?? 0, hint: '方向未解决'},
  ];
  const icons: IconName[] = ['alert','layers','check','chain','arrow','evidence'];
  return <div className="metric-grid overview-metrics">{cards.map(({title, value, hint},i) => (
    <article className={'metric overview-metric metric-tone-'+i} key={title}>
      <span className="metric-icon"><Icon name={icons[i % icons.length]}/></span><div>
      <span className="metric-title">{title}</span>
      <strong>{value.toLocaleString()}</strong>
      <small className="metric-hint">{hint}</small>
      </div>
    </article>
  ))}</div>;
}

// -- Time trend -----------------------------------------------------------
function AlertTrend({summary}: {summary: StageSummary}) {
  const series = summary.summary.time_series;
  if (!series.length) return <Notice>暂无告警时间序列数据。</Notice>;
  const max = Math.max(1, ...series.map(b => b.count));
  const width = 720, height = 160, pad = 24;
  const n = series.length;
  const step = (width - pad * 2) / Math.max(1, n - 1);
  const points = series.map((b, i) => ({x: pad + i * step, y: height - pad - (b.count / max) * (height - pad * 2), count: b.count, time: b.time}));
  const path = points.map((p, i) => (i ? 'L' : 'M') + p.x.toFixed(1) + ' ' + p.y.toFixed(1)).join(' ');
  const area = path + ` L${points[points.length - 1].x.toFixed(1)} ${height - pad} L${pad} ${height - pad} Z`;
  const total = series.reduce((a, b) => a + b.count, 0);
  const startT = series[0].time, endT = series[series.length - 1].time;
  return <div className="trend-wrap">
    <div className="trend-meta"><span>共 {total} 条保留告警 · {n} 个时间桶</span><span className="muted">{startT.slice(11, 16)} — {endT.slice(11, 16)} UTC</span></div>
    <svg className="trend-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label="告警时间分布折线图">
      <defs><linearGradient id="trend-fill" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="#1677ff" stopOpacity="0.22"/><stop offset="100%" stopColor="#1677ff" stopOpacity="0.02"/></linearGradient></defs>
      {[0,1,2,3].map(i=><g key={i}><line x1={pad} y1={pad+i*(height-2*pad)/3} x2={width-pad} y2={pad+i*(height-2*pad)/3} stroke="#edf2f8"/><text x="2" y={pad+i*(height-2*pad)/3+4} fill="#8b9ab0" fontSize="10">{Math.round(max*(1-i/3))}</text></g>)}
      <line x1={pad} y1={height - pad} x2={width - pad} y2={height - pad} stroke="#dce6ec"/>
      <path d={area} fill="url(#trend-fill)"/>
      <path d={path} fill="none" stroke="#1677ff" strokeWidth="2" strokeLinejoin="round"/>
      {points.map((p, i) => <circle key={i} cx={p.x} cy={p.y} r="2.5" fill="#1677ff"><title>{p.time.slice(11, 19)} UTC · {p.count} 条告警</title></circle>)}
    </svg>
    <div className="trend-axis"><span>{startT.slice(11, 16)}</span><span>{endT.slice(11, 16)}</span></div>
  </div>;
}

// -- Relation decision distribution (donut) -------------------------------
function RelationDistribution({data}: {data: StageAnalysis}) {
  const c = data.counts;
  const directed = c.directed_count ?? 0, undirected = c.undirected_count ?? 0, noRelation = c.no_relation_count ?? 0;
  const total = directed + undirected + noRelation;
  if (!total) return <Notice>暂无关系决策数据。</Notice>;
  const segs = [
    {label: '有向关系', value: directed, color: '#1677ff'},
    {label: '无向关系', value: undirected, color: '#7d6a9f'},
    {label: '不建立关系', value: noRelation, color: '#c3ccd4'},
  ].filter(s => s.value > 0);
  const R = 54, C = 2 * Math.PI * R;
  let offset = 0;
  return <div className="donut-wrap">
    <svg viewBox="0 0 160 160" className="donut" role="img" aria-label="关系决策分布">
      <circle cx="80" cy="80" r={R} fill="none" stroke="#eef2f5" strokeWidth="18"/>
      {segs.map(s => {
        const len = (s.value / total) * C;
        const el = <circle key={s.label} cx="80" cy="80" r={R} fill="none" stroke={s.color} strokeWidth="18" strokeDasharray={`${len} ${C - len}`} strokeDashoffset={-offset} transform="rotate(-90 80 80)"><title>{s.label} · {s.value}</title></circle>;
        offset += len;
        return el;
      })}
      <text x="80" y="74" textAnchor="middle" className="donut-center">{total}</text>
      <text x="80" y="92" textAnchor="middle" className="donut-center-sub">阶段关系决策</text>
    </svg>
    <ul className="donut-legend">{segs.map(s => <li key={s.label}><i style={{background: s.color}}/><span>{s.label}</span><b>{s.value}</b></li>)}</ul>
  </div>;
}

// -- Source distribution (horizontal bars) --------------------------------
function SourceDistribution({summary}: {summary: StageSummary}) {
  const rows = summary.summary.source_namespace;
  if (!rows.length) return <Notice>暂无数据源分布数据。</Notice>;
  const max = Math.max(1, ...rows.map(r => r.count));
  const total = rows.reduce((a, b) => a + b.count, 0);
  return <div className="source-dist">
    {rows.map(r => <div className="source-row" key={r.value}>
      <span className="source-name">{sourceNamespaceLabel(r.value)}</span>
      <div className="source-bar"><i style={{width: `${(r.count / max) * 100}%`}}/></div>
      <b className="source-count">{r.count}</b>
    </div>)}
    <p className="muted source-total">共 {total} 条告警 · {rows.length} 类数据源</p>
  </div>;
}

// -- Chain overview (horizontal stage flow) -------------------------------
function ChainFlow({chain, stages, onOpen}: {chain: StageChain; stages: Stage[]; onOpen: () => void}) {
  const chainStages = chain.stage_ids.map(id => stages.find(s => s.stage_id === id)).filter((s): s is Stage => !!s)
    .sort((a, b) => a.start_time.localeCompare(b.start_time) || a.stage_id.localeCompare(b.stage_id));
  const spanMin = chainStages[0]?.start_time, spanMax = chainStages[chainStages.length - 1]?.end_time;
  const totalAlerts = chainStages.reduce((a, s) => a + s.alert_count, 0);
  return <div className="chain-flow-card">
    <div className="chain-flow-scroll">
      <div className="chain-flow">
        {chainStages.slice(0,5).map((s, i) => (
          <div className="chain-flow-node" key={s.stage_id}>
            <span className="flow-index">{i + 1}</span>
            <span className="flow-behavior">{behaviorName(s.behavior)}</span>
            <small className="flow-meta">{s.alert_count} 条告警 · {s.source_types.map(sourceLabel).join('/')}</small>
            <small className="flow-time">{s.start_time.slice(11, 19)}</small>
          </div>
        ))}
      </div>
    </div>
    <div className="chain-flow-summary">
      <div className="chain-stats">
        <span>阶段 <b>{chain.stage_count}</b></span>
        <span>告警 <b>{totalAlerts}</b></span>
        <span>有向关系 <b>{chain.directed_count ?? 0}</b></span>
        <span>无向关系 <b>{chain.undirected_count ?? 0}</b></span>
        {spanMin && spanMax && <span>时间跨度 <b>{Math.round((new Date(spanMax).getTime() - new Date(spanMin).getTime()) / 60000)} 分钟</b></span>}
      </div>
      <button className="primary chain-open" onClick={onOpen}>查看完整攻击链 →</button>
    </div>
    <p className="sequence-note">按观测时间展示前 {Math.min(5,chainStages.length)} 个阶段{chainStages.length>5?` · 另有 ${chainStages.length-5} 个阶段`:''}；排列顺序不代表因果关系。</p>
  </div>;
}

// -- Recent chains table --------------------------------------------------
function RecentChains({data, onOpen}: {data: StageAnalysis; onOpen: (chainId: string) => void}) {
  const chains = sortChains(data.chains).slice(0,4);
  const stageById = new Map(data.stages.map(s => [s.stage_id, s]));
  const chainAssets = (c: StageChain) => {
    const hosts = new Set<string>();
    c.stage_ids.forEach(id => { const s = stageById.get(id); s?.source_types.forEach(t => hosts.add(t)); });
    return [...hosts].map(sourceLabel).join(' / ');
  };
  const chainBehavior = (c: StageChain) => {
    const set = new Set<string>();
    c.stage_ids.forEach(id => { const s = stageById.get(id); if (s) set.add(behaviorName(s.behavior)); });
    return [...set].join(' / ');
  };
  return <div className="table-scroll">
    <table className="recent-chains-table">
      <thead><tr><th>攻击链</th><th>阶段数</th><th>关系数</th><th>告警数</th><th>有向/无向</th><th>主要数据源</th><th>主要行为</th><th>操作</th></tr></thead>
      <tbody>
        {chains.map((c, i) => {
          const stages = c.stage_ids.map(id => stageById.get(id)).filter((s): s is Stage => !!s);
          const alerts = stages.reduce((a, s) => a + s.alert_count, 0);
          return <tr key={c.chain_id}>
            <td><button className="text-button" onClick={()=>onOpen(c.chain_id)}>攻击链 {i+1}</button><span className="chain-id"><StableId value={c.chain_id}/></span></td>
            <td>{c.stage_count}</td>
            <td>{c.relation_count}</td>
            <td>{alerts}</td>
            <td>{c.directed_count ?? 0} / {c.undirected_count ?? 0}</td>
            <td>{chainAssets(c)}</td>
            <td>{chainBehavior(c)}</td>
            <td><button onClick={() => onOpen(c.chain_id)}>查看</button></td>
          </tr>;
        })}
      </tbody>
    </table>
  </div>;
}

// -- Main page ------------------------------------------------------------
export default function OverviewPage({data, summary, onOpenChain, onNavigate}: {
  analysisId: string;
  data: StageAnalysis;
  summary: StageSummary;
  onOpenChain: (chainId: string) => void;
  onNavigate: (view: string, query?: string) => void;
}) {
  const chains = sortChains(data.chains);
  const activeChain = chains[0];
  const activeStages = activeChain ? data.stages.filter(s=>activeChain.stage_ids.includes(s.stage_id)) : [];
  const [query,setQuery]=useState('');
  const [showDistributions,setShowDistributions]=useState(false);

  return <div className={'overview-page'+(showDistributions?' show-distributions':'')} data-analysis-id={data.analysis_id}>
    <div className="scope-toolbar"><form className="scope-search" onSubmit={e=>{e.preventDefault();onNavigate('alerts',query);}}><Icon name="search"/><input aria-label="搜索告警或阶段" placeholder="搜索告警 ID、阶段 ID 或行为…" value={query} onChange={e=>setQuery(e.target.value)}/><button type="submit">搜索</button></form><span className="snapshot-range"><Icon name="clock"/>{summary.summary.time_series[0]?.time.slice(0,10) ?? '当前快照'} · 快照时段</span><span className="badge verified">{data.official?'正式验收基线':data.source_stage===9?'当前批次':'历史快照'} · {data.source_stage===9?'⑨ 攻击链重建':'阶段分析'}</span></div>

    <MetricCards data={data}/>
    <button className="mobile-distribution-toggle" aria-expanded={showDistributions} onClick={()=>setShowDistributions(v=>!v)}>{showDistributions?'收起':'展开'}关系与来源分布</button>

    <div className="overview-grid">
      <section className="panel overview-panel">
        <div className="section-heading"><h2>告警时间分布</h2><span className="muted">保留告警按分钟聚合</span></div>
        <AlertTrend summary={summary}/>
      </section>
      <section className="panel overview-panel overview-relations-panel">
        <div className="section-heading"><h2>关系决策分布</h2><span className="muted">阶段关系判定</span></div>
        <RelationDistribution data={data}/>
      </section>
    </div>

    <div className="overview-grid overview-secondary"><section className="panel overview-panel">
      <div className="section-heading"><h2>重点攻击链概览</h2><span className="muted">{activeChain?.stage_count ?? 0} 个阶段 · 观测时间序列</span></div>
      {activeChain ? <ChainFlow chain={activeChain} stages={activeStages} onOpen={() => onOpenChain(activeChain.chain_id)}/>
        : <Notice>暂无攻击链数据。</Notice>}
    </section>

    <section className="panel overview-panel overview-sources-panel">
      <div className="section-heading"><h2>多源安全告警分布</h2><span className="muted">按数据源命名空间统计</span></div>
      <SourceDistribution summary={summary}/>
    </section></div>

    <section className="panel overview-panel">
      <div className="section-heading"><h2>攻击链摘要</h2><button className="text-button" onClick={()=>onNavigate('stages')}>查看全部 {chains.length} 条 →</button></div>
      <RecentChains data={data} onOpen={onOpenChain}/>
    </section>

    <p className="overview-footnote"><span className="status-dot"/>只读分析快照 · {data.counts.input_count} 条告警 · 图结构不代表已确认攻击<button className="text-button" onClick={()=>onNavigate('records')}>查看分析记录 →</button></p>
  </div>;
}
