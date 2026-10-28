/**
 * Error presentation: keep the raw backend code visible for support/reproduction,
 * add a Chinese explanation and a retry hint on top of it.
 */
export interface DescribedError {
  code: string;
  title: string;
  message: string;
  retryable: boolean;
}

const KNOWN_ERRORS: Record<string, Omit<DescribedError, 'code'>> = {
  network_unavailable: {
    title: '无法连接分析服务',
    message: '请确认演示服务仍在运行，然后重试。已展示的数据不会被清除。',
    retryable: true,
  },
  invalid_response: {
    title: '分析服务返回了无法读取的数据',
    message: '快照可能不完整。可以重试；若持续失败，请检查服务日志。',
    retryable: true,
  },
  request_failed: {
    title: '请求未能完成',
    message: '分析服务没有返回可用的结果，可以重试。',
    retryable: true,
  },
  analysis_not_found: {
    title: '未找到该分析快照',
    message: '请确认分析 ID 完整无误，或重新打开演示程序打印的地址。',
    retryable: false,
  },
  analysis_not_ready: {
    title: '分析仍在处理中',
    message: '该快照尚未完成冻结，请稍后刷新。',
    retryable: true,
  },
  snapshot_integrity_error: {
    title: '分析快照校验失败',
    message: '快照文件可能损坏或被外部修改。请重新生成或重新打开演示。',
    retryable: false,
  },
  snapshot_identity_error: {
    title: '分析快照身份不一致',
    message: '快照内容与分析 ID 不匹配，不能作为正式证据展示。',
    retryable: false,
  },
  snapshot_scope_mismatch: {
    title: '事件与分析范围不一致',
    message: '当前事件不属于该分析快照，已停止展示以避免混合证据。',
    retryable: false,
  },
  incident_not_found: {
    title: '未找到该安全事件',
    message: '事件可能不属于当前分析，请返回调查队列重新选择。',
    retryable: false,
  },
  alert_not_found: {
    title: '未找到该设备告警',
    message: '告警可能已被快照裁剪，或不属于当前事件。',
    retryable: false,
  },
  incident_snapshot_error: {
    title: '安全事件快照不可读取',
    message: '事件主体读取失败；可以重试，或返回调查队列选择其他事件。',
    retryable: true,
  },
  chain_snapshot_error: {
    title: '攻击链快照不可读取',
    message: '事件本身可读取，但攻击链构造结果缺失或损坏。',
    retryable: true,
  },
  observations_snapshot_error: {
    title: '观测字段不可读取',
    message: '成员与观测字段读取失败；证据和攻击链可能仍可查看。',
    retryable: true,
  },
  ai_generation_timeout: {
    title: 'AI 研判生成超时',
    message: '本地服务在 45 秒内没有返回结果；上次已验证的报告仍保留。可以重试或先查看证据。',
    retryable: true,
  },
  ai_generation_cancelled: {
    title: '已取消生成',
    message: '本次 AI 研判已取消，没有写入新的正式报告。',
    retryable: true,
  },
  ai_grounding_unavailable: {
    title: 'AI 研判不可用',
    message: '本地证据未通过锚定校验，本次不会生成正式结论。',
    retryable: false,
  },
  ai_context_grounding_failed: {
    title: 'AI 上下文校验失败',
    message: '节点、边或证据引用不完整，无法安全生成研判。',
    retryable: false,
  },
  presentation_requires_validated_report: {
    title: '报告未通过发布校验',
    message: '只有通过证据锚定校验的报告才能作为正式结论展示。',
    retryable: false,
  },
  presentation_report_invalid: {
    title: '已保存报告损坏',
    message: '报告索引存在但内容不可读。可以重新请求 AI 研判。',
    retryable: true,
  },
  score_diagnostic_integrity_error: {
    title: '评分诊断不可读取',
    message: '诊断文件校验失败；事件与证据仍可正常查看。',
    retryable: false,
  },
  invalid_pagination: {
    title: '分页参数无效',
    message: '页码或每页数量超出允许范围，已回退到第一页。',
    retryable: false,
  },
  invalid_workbench_filter: {
    title: '筛选条件无效',
    message: '筛选值不在允许范围内，已回退到默认筛选。',
    retryable: false,
  },
  invalid_time_filter: {
    title: '时间筛选无效',
    message: '时间格式不符合 UTC ISO 8601，请重新选择。',
    retryable: false,
  },
  invalid_time_interval: {
    title: '时间范围无效',
    message: '结束时间必须晚于开始时间，请重新选择。',
    retryable: false,
  },
  unknown_query_parameter: {
    title: '请求包含未知参数',
    message: '链接可能来自旧版本，请返回工作台重新进入。',
    retryable: false,
  },
  unknown_or_duplicate_query_parameter: {
    title: '请求参数重复或未知',
    message: '链接可能被拼接了重复参数，请返回工作台重新进入。',
    retryable: false,
  },
};

export function describeError(raw: string | null | undefined): DescribedError {
  const code = (raw ?? '').trim() || 'request_failed';
  const known = KNOWN_ERRORS[code] ?? (code.startsWith('invalid_filter:')
    ? {
        title: '筛选值无效',
        message: '该筛选值不在允许范围内，已回退到默认筛选。',
        retryable: false,
      }
    : undefined);
  return {
    code,
    title: known?.title ?? '请求未能完成',
    message: known?.message ?? '分析服务返回了未识别的错误码，可以重试或查看诊断信息。',
    retryable: known?.retryable ?? true,
  };
}
