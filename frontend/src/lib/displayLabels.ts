/** Display only: never rewrite API values, facts, catalog or raw alert text. */
const label = (map: Record<string, string>, value: string) => map[value] ?? value ?? '未知';
export const severityLabel = (v: string) => label({unknown:'未知', informational:'提示', low:'低', medium:'中', high:'高', critical:'严重'},v);
export const categoryLabel = (v: string) => label({unknown:'未分类',reconnaissance:'侦察',initial_access:'初始访问',web_attack:'Web 攻击',authentication:'身份认证',process_execution:'进程执行',command_execution:'命令执行',persistence:'持久化',privilege_escalation:'权限提升',defense_evasion:'防御规避',credential_access:'凭据访问',discovery:'发现',lateral_movement:'横向移动',command_and_control:'命令与控制',collection:'收集',exfiltration:'数据外传',impact:'影响'},v);
export const statusLabel = (v: string) => label({queued:'等待处理',running:'分析中',completed:'分析完成',succeeded:'生成成功',provider_unavailable:'提供方不可用',provider_failed:'提供方失败',parsing_failed:'响应解析失败',grounding_failed:'证据锚定失败',grounding_rejected:'证据锚定拒绝',failed:'失败',incomplete:'分析不完整',unknown:'未知',pending:'等待处理',new:'新建',investigating:'调查中',resolved:'已解决',false_positive:'已判为误报',complete:'流程完整',partial:'部分链',validated:'已验证',rejected:'已拒绝',verified:'已验证',available:'可用',unavailable:'不可用',not_generated:'待生成',generating:'生成中',partially_rejected:'部分拒绝'},v);
export const aiLabel = (v: string) => label({not_generated:'待生成',generating:'生成中',completed:'已完成',partially_rejected:'部分拒绝',unavailable:'AI 不可用',failed:'生成失败'},v);
export const sourceLabel = (v: string) => label({wazuh:'Wazuh',suricata:'Suricata',aminer:'AMiner',waf:'WAF',edr:'EDR',ids:'IDS',siem:'SIEM',windows_security:'Windows 安全',cloud_security:'云安全',other:'其他'},v);
export const fieldLabel = (v: string) => label({src_ip:'来源 IP',dst_ip:'目标 IP',host:'主机',account:'账号',session:'会话',process:'进程',parent_process:'父进程',url:'URL',domain:'域名',file:'文件',command:'命令',timestamp:'观测时间',source_type:'告警来源',source_namespace:'来源命名空间',source_record_id:'来源记录 ID',category:'类别',severity:'设备观测等级',sensor:'设备',rule_id:'规则 ID',signature:'规则特征'},v);
export const entityLabel = (v: string) => label({IP:'IP',HOST:'主机',ACCOUNT:'账号',SESSION:'会话',PROCESS:'进程',URL:'URL',DOMAIN:'域名',FILE:'文件',COMMAND:'命令'},v);
export const componentLabel = (v: string) => label({time:'时间证据',entity:'共享实体证据',relation:'显式传播关系',behavior:'行为兼容',source:'独立来源互补',conflict:'冲突惩罚',duplicate:'疑似重复惩罚'},v);
export const scoreComponents = ['time','entity','relation','behavior','source','conflict','duplicate'] as const;
export const relationLabel = (v: string) => label({PROCESS_CAUSAL:'父子进程因果',REQUEST_TO_PROCESS:'请求触发进程',ACCOUNT_PIVOT:'账号跨主机传播',NETWORK_PIVOT:'网络传播',SESSION_FLOW:'会话流转',confirmed_independent:'已确认独立来源',confirmed_same_origin:'已确认同源',unknown:'未知'},v);
export const kindLabel = (v: string) => label({alert:'告警',node:'节点',fact:'事实',inference:'推断',recommendation:'建议',attack_mapping:'ATT&CK 映射'},v);
export const analysisMetrics = [['input_count','输入告警'],['canonical_alert_count','标准化告警'],['representative_count','去重代表'],['incident_count','安全事件'],['representative_singleton_incident_count','单代表告警事件'],['correlated_multi_alert_incident_count','关联聚合事件'],['correlation_edge_count','已验证关联'],['chain_edge_count','有向攻击链边']] as const;
export const incidentKindLabel = (n: number | undefined) => n === undefined ? '代表成员数未提供' : n === 1 ? '单代表告警事件' : '关联聚合事件';

export const reasonLabel = (v: string) => label({node_basis:'节点构造依据',time_gap:'时间接近',shared_entity:'共享实体',explicit_relation:'显式传播关系',behavior_transition:'行为兼容',source_complement:'来源互补',conflict:'冲突控制',duplicate:'重复相似度',direction:'方向判定'},v);
export const reasonMessageLabel = (message: string, code = '') => message.replace(/\b(authentication|unknown|process_execution|privilege_escalation|web_attack|command_execution|initial_access|lateral_movement)\b/g,v=>v==='unknown' && code==='source_complement' ? relationLabel(v) : categoryLabel(v)).replace(/\b(confirmed_independent|confirmed_same_origin)\b/g,relationLabel).replace(/\b(ACCOUNT|HOST|SESSION|PROCESS|COMMAND|FILE|DOMAIN)\b/g,entityLabel);

export const originLabel = (v: string) => label({deterministic:'确定性事实模板',llm:'AI 生成',mixed:'AI 与确定性模板'},v);

// Stage behavior → Chinese label (display only; used by overview and workbench).
export const behaviorName = (v: string) => label({WEB_EXPLOIT:'Web 利用', EXECUTION:'执行活动', CREDENTIAL_ACTIVITY:'凭据活动', FILE_ACTIVITY:'文件活动', NETWORK_ACTIVITY:'网络活动', AUTHENTICATION:'身份认证', UNKNOWN:'未分类行为', PROCESS_EXECUTION:'进程执行'}, v);
