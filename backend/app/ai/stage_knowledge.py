"""Evidence-qualified security semantics, separate from algorithm behavior labels.

These are publication rules for explanations, never relation/chain decisions.
Raw event operations remain authoritative: a command argument is not proof that
its referenced file was read, and a parent_process field is not a creation event.
"""
import json
from urllib.parse import unquote_plus

from .stage_context import scalar_pointers

KNOWLEDGE = {
    'insufficient': ('证据不足', '当前证据不足以确定更具体的安全行为。', None),
    'process_execution': ('进程执行', '观测到进程启动或命令执行，可能涉及系统操作；是否为未授权执行仍需核实。',
                          '此类执行可能提供进一步命令执行、载荷运行或系统操作能力。'),
    'server_shell': ('疑似服务进程关联 Shell 执行', '记录表现出服务进程上下文中的 Shell 执行特征，可能涉及服务器侧命令执行。',
                     '若执行未经授权，可能使服务权限被用于运行命令或访问主机资源。'),
    'file_access': ('文件操作', '记录表现出文件读取、创建或修改行为，是否涉及敏感内容仍需核实。',
                    '文件操作可能带来信息暴露、内容篡改或后续载荷运行风险。'),
    'credential_file': ('疑似凭据材料访问', '文件操作涉及常见凭据材料路径，可能与凭据访问有关；不证明凭据已泄露。',
                        '若敏感凭据材料被未经授权地读取，可能带来账户滥用或横向访问风险。'),
    'authentication': ('认证活动', '存在认证或会话活动，可能涉及账户使用；认证成功本身不证明账户失陷。',
                       '异常认证或会话使用可能涉及凭据攻击、账户滥用或未授权访问。'),
    'network': ('网络通信', '记录表现出网络连接或流量观测，可能涉及跨主机通信；不能据此确认外传。',
                '未经授权的网络连接可能用于远程访问或传输数据，需内容和接收端证据确认用途。'),
    'http_request': ('HTTP 请求', '存在 HTTP 请求，可能涉及对应用接口的访问，不能仅凭状态码确认利用成功。',
                     '异常应用请求可能影响接口安全、业务数据或服务可用性。'),
    'sql_pattern': ('疑似 SQL 注入请求', '请求参数表现出 SQL 注入特征，是否执行到数据库仍缺少后端证据。',
                    '若后端存在可利用缺陷，此类输入可能导致查询逻辑改变或数据访问风险。'),
    'traversal_pattern': ('疑似路径穿越请求', '请求参数表现出路径穿越特征，不能据此确认目标文件已被读取。',
                          '若路径校验存在缺陷，此类输入可能导致越权文件访问。'),
}

ROLE_POINTERS = {
    'host': ('/hostname', '/server_host', '/host', '/host_id', '/agent/name'),
    'account': ('/user', '/account', '/username', '/data/win/eventdata/user'),
    'operation': ('/operation', '/event/action', '/event_type', '/action'),
    'process': ('/process_name', '/process/name', '/data/win/eventdata/image', '/executable'),
    'parent_process': ('/parent_process_name', '/process/parent/name', '/data/win/eventdata/parentImage'),
    'command_line': ('/command_line', '/process/command_line', '/data/win/eventdata/commandLine', '/command'),
    'file': ('/file_path', '/file/path', '/data/win/eventdata/targetFilename'),
    'registry': ('/registry_path', '/registry/key'),
    'src_ip': ('/src_ip', '/source_ip', '/client_ip', '/source/ip'),
    'dst_ip': ('/dst_ip', '/dest_ip', '/server_ip', '/destination/ip'),
    'dst_port': ('/dst_port', '/dest_port', '/destination_port', '/server_port', '/destination/port'),
    'method': ('/method', '/http/http_method', '/http/request/method'),
    'url': ('/uri', '/url', '/http/url'),
    'parameters': ('/query', '/payload', '/request_body', '/http/request/body/content'),
    'result': ('/result', '/event/outcome', '/application_result'),
    'status_code': ('/status_code', '/http/status'),
    'session': ('/session_id', '/logon_id', '/connection_id'),
    'process_id': ('/process_id', '/process/pid'),
    'parent_process_id': ('/parent_process_id', '/process/parent/pid'),
}
ROLE_LABELS = dict(host='主机', account='账户', operation='原始操作', process='进程',
    parent_process='父进程字段', command_line='命令行', file='文件', registry='注册表',
    src_ip='源地址', dst_ip='目标地址', dst_port='目标端口', method='HTTP 方法', url='请求地址',
    parameters='参数/载荷', result='结果字段', status_code='响应状态', session='会话/连接',
    process_id='进程 ID', parent_process_id='父进程 ID')


def fact_from_alert(alert):
    aid = alert['alert_id']
    fields = dict(scalar_pointers(alert['raw_alert']))
    roles = {}
    for role, candidates in ROLE_POINTERS.items():
        for pointer in candidates:
            if pointer in fields:
                roles[role] = dict(alert_id=aid, pointer=pointer, value=fields[pointer])
                break
    # Unknown raw fields are retained and can be inspected even when no semantic
    # role is recognized. A signature is only a device assertion, never an outcome.
    selected = list(roles.values())
    if not selected:
        selected = [dict(alert_id=aid, pointer=p, value=v) for p, v in list(fields.items())[:12]]
    if not selected:
        selected = [dict(alert_id=aid, pointer='', value=alert['raw_alert'])]
    return dict(fact_id='fact_' + aid, evidence_refs=[aid], roles=roles,
        field_refs=selected, eligible_codes=qualify(roles), confirmed=confirmed(roles))


def qualify(roles):
    """Qualification for cautious interpretation, not detection or correlation."""
    val = lambda key: str(roles.get(key, {}).get('value', ''))
    operation = val('operation').lower()
    codes = ['insufficient']
    if operation in {'processstart', 'processcreate', 'commandexecution', 'exec', 'process_create'}:
        codes.append('process_execution')
        if (val('parent_process').lower() in {'nginx', 'httpd', 'apache2', 'w3wp.exe', 'php-fpm'} and
                val('process').lower() in {'sh', 'bash', 'cmd.exe', 'powershell.exe', '/bin/sh', '/bin/bash'}):
            codes.append('server_shell')
    if operation in {'fileread', 'filecreate', 'filemodify', 'read', 'write', 'file_read', 'file_create'} and val('file'):
        codes.append('file_access')
        path = val('file').lower()
        if any(token in path for token in ('/.ssh/', '/etc/shadow', 'ntds.dit', '/sam')):
            codes.append('credential_file')
    if operation in {'credential_accepted', 'pam_account', 'session_open', 'authentication',
                     'login', 'logon', 'authentication_failure', 'authentication_failed', 'login_failed'}:
        codes.append('authentication')
    if operation.lower() == 'networkconnection' or (val('src_ip') and val('dst_ip')):
        codes.append('network')
    if val('method') and val('url'):
        codes.append('http_request')
        params = unquote_plus(val('parameters')).lower()
        if ' or 1=1' in params or 'union select' in params or "' or '" in params:
            codes.append('sql_pattern')
        if '../' in params or '..\\' in params:
            codes.append('traversal_pattern')
    return codes


def confirmed(roles):
    val = lambda key: roles.get(key, {}).get('value')
    # Explicit device event (not rule name, command intent or an HTTP response).
    # Limit the published conclusion to the operation actually recorded.
    op = str(val('operation')).lower()
    if str(val('result')).lower() in {'failed', 'failure', 'denied', 'error', 'blocked'}:
        return None
    if val('file') and op in {'filecreate', 'file_create'}:
        return 'file_created'
    if val('account') and op in {'credential_accepted', 'login', 'logon'} and val('result') == 'success':
        return 'authentication_succeeded'
    return None


def render_fact(fact):
    quote = lambda v: json.dumps(v, ensure_ascii=False)
    roles = fact['roles']
    if roles:
        value = lambda key: quote(roles[key]['value'])
        used = set()
        if 'method' in roles and 'url' in roles:
            subject = '源地址 ' + value('src_ip') if 'src_ip' in roles else '未注明源地址的客户端'
            lead = f"原始请求记录：{subject} 使用 {value('method')} 请求 {value('url')}"
            used.update({'src_ip', 'method', 'url'})
        elif 'operation' in roles:
            subject = ('主机 ' + value('host') + ' 上，' if 'host' in roles else '')
            subject += ('账户 ' + value('account') + ' 的' if 'account' in roles else '')
            subject += '进程 ' + value('process') if 'process' in roles else '事件'
            lead = '原始事件记录：' + subject + '记录了 ' + value('operation') + ' 操作'
            used.update({'host', 'account', 'process', 'operation'})
        else:
            lead = '原始告警记录'
        remaining = [ROLE_LABELS[k] + '=' + value(k) for k in roles if k not in used]
        return lead + ('；' + '；'.join(remaining) if remaining else '') + '。'
    return '原始告警字段：' + '；'.join(p['pointer'] + '=' + quote(p['value']) for p in fact['field_refs']) + '。'


def render_confirmed(fact):
    quote = lambda role: json.dumps(fact['roles'][role]['value'], ensure_ascii=False)
    if fact['confirmed'] == 'file_created':
        return '已确认的观测仅为设备记录了 FileCreate 文件创建事件：' + quote('file') + '；缺少独立落盘核验，不证明文件恶意性或执行成功。'
    if fact['confirmed'] == 'authentication_succeeded':
        return '认证记录确认账户 ' + quote('account') + ' 本次认证成功；不证明账户已失陷或获得管理员权限。'
    raise ValueError('unsupported_confirmed_impact')


def make_stage_evidence(stage, alerts):
    facts = [fact_from_alert(a) for a in alerts]
    roles = set(k for fact in facts for k in fact['roles'])
    codes = sorted({c for f in facts for c in f['eligible_codes']})
    missing = []
    if any('process' in f['roles'] and 'command_line' not in f['roles'] for f in facts):
        missing.append('部分进程记录缺少完整 command_line，无法确认对应事件的实际命令内容。')
    if 'process' in roles and 'parent_process' not in roles:
        missing.append('缺少 parent process detail，无法确认进程创建上下文。')
    if 'http_request' in codes:
        if any('method' in f['roles'] and 'parameters' not in f['roles'] for f in facts):
            missing.append('部分请求缺少参数/请求体或 Payload，无法确认完整请求内容。')
        missing.append('缺少后端执行及数据访问结果，HTTP 响应码不能单独证明利用成功。')
    if 'authentication' in codes:
        if not any(f['confirmed'] == 'authentication_succeeded' for f in facts):
            missing.append('当前没有明确的成功认证证据，不能确认账户已成功登录或已失陷。')
        missing.append('缺少未授权账户使用、凭据泄露或权限提升证据，不能确认账户失陷。')
    if 'file_access' in codes or 'network' in codes:
        missing.append('缺少文件内容、传输内容及接收端证据，不能确认数据或凭据已经泄露。')
    if codes == ['insufficient']:
        missing.append('原始字段不足以识别具体操作；不能仅凭 Stage Behavior 标签补全行为。')
    missing.append('告警记录不等于攻击成功；当前证据不能确认主机已被控制或取得管理员权限。')
    return dict(facts=facts, eligible_codes=codes,
        interpretation_options={code: dict(label=KNOWLEDGE[code][0], description=KNOWLEDGE[code][1],
                                           potential_impact=KNOWLEDGE[code][2]) for code in codes},
        confirmed_fact_ids=[f['fact_id'] for f in facts if f['confirmed']], missing_evidence=missing)
