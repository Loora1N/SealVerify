// 属性来自原始 OFD 的本机 Python 解析；不使用阅读副本进行签章检查。
const labels = {
  version: '版本', id: '标识', seal_id: '印章 ID', vendor: '厂商标识', type: '类型',
  name: '印章名称', created: '制作时间（声明）', valid_start: '有效期起', valid_end: '有效期止',
  cert_list_type: '授权证书列表类型', certificates: '印章授权证书', certificate_digests: '授权证书摘要',
  property: '印章属性', picture: '印章图像', width_mm: '宽度（毫米）', height_mm: '高度（毫米）',
  maker_certificate: '制章者证书', signer_certificate: '签章者证书', algorithm: '算法 OID',
  signature: '签名值', certificate_signature: '证书签名值（颁发者签名）', declared_time: '声明的签章时间（未验证）', data_hash: '声明的原文杂凑',
  property_info: '原文属性（厂商声明，未解释保护范围）', extensions: '扩展数据', timestamp: '时间戳',
  data: '数据摘要', bytes: '字节数', sha256: 'SHA-256 摘要', hex_preview: '十六进制预览',
  truncated: '预览已截断', subject: '主体', issuer: '颁发者', serial_hex: '序列号（十六进制）',
  not_before: '有效期起', not_after: '有效期止', signature_algorithm: '证书签名算法 OID',
  public_key_algorithm: '公钥算法 OID', key_usage: '密钥用途', basic_constraints: '基本约束',
  ca: 'CA 标志（不代表可信根）', path_len_constraint: '路径长度约束', verification: '验证状态',
  oid: 'OID', critical: '关键扩展', value: '值', policy: '时间戳策略', serial: '序列号',
  content_type: 'CMS 内容类型', imprint: '消息印记', imprint_algorithm: '印记算法 OID',
  signer_count: 'CMS 签名者数量', details: '时间戳内容',
};
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function tree(value) {
  if (value === null || value === undefined) return element('span', '无可解析数据');
  if (typeof value !== 'object') return element('span', value === 'not_performed' ? '未验证' : typeof value === 'boolean' ? (value ? '是' : '否') : String(value));
  const list = element('dl', undefined, 'property-list');
  for (const [key, item] of Object.entries(value)) {
    if (key === 'preview') continue;
    if (key === 'signature' || key === 'certificate_signature') {
      const kind = key === 'certificate_signature' ? 'certificate' : 'maker_certificate' in value ? 'seal' : 'document';
      const title = { certificate: '证书签名值（颁发者签名）', seal: '制章签名值', document: '电子签章签名值' }[kind];
      list.append(element('dt', title));
      const cell = element('dd'); cell.append(signatureValue(item, kind, title)); list.append(cell);
      continue;
    }
    list.append(element('dt', labels[key] || key));
    const cell = element('dd');
    cell.append(item && typeof item === 'object' && 'hex_preview' in item ? section(`${item.bytes} 字节 · 查看摘要`, tree(item)) : tree(item));
    list.append(cell);
  }
  if (!Object.keys(value).length) list.append(element('dd', '无'));
  return list;
}
function signatureValue(value, kind, title) {
  const card = element('div', undefined, 'signature-value');
  card.dataset.signatureKind = kind; card.setAttribute('role', 'group'); card.setAttribute('aria-label', title);
  const decoded = value?.decoded;
  if (!decoded) { card.append(element('p', '签名值无法解析，请查看问题记录。', 'error')); return card; }
  card.append(element('p', `${decoded.algorithm} · ${decoded.algorithm_oid || '算法 OID 缺失'}`),
    element('p', `${value.bytes} 字节 · 属性展示，验证结论见检查明细`, 'muted'));
  if (decoded.message) card.append(element('p', decoded.message, 'error'));
  for (const [key, label] of [['r_hex', 'r（十六进制，32 字节）'], ['s_hex', 's（十六进制，32 字节）'],
    ['signature_hex', '完整签名值（十六进制）']]) {
    if (decoded[key] === undefined) continue;
    const code = element('code', decoded[key], 'signature-hex'); code.dataset.component = key;
    card.append(element('p', label), code);
  }
  return card;
}
function section(title, content, open = false) {
  const details = element('details', undefined, 'signature-section');
  details.open = open; details.append(element('summary', title), content); return details;
}

function formatSection(report, title = '第一步：电子签章数据格式验证', role = 'signature') {
  const names = { passed: '通过', failed: '失败', indeterminate: '无法确定', skipped: '跳过', error: '错误', not_applicable: '不适用' };
  const wrapper = element('div', undefined, 'format-validation');
  if (!report) { wrapper.append(element('p', '未获得格式检查结果。', 'error')); return wrapper; }
  wrapper.dataset.formatStatus = report.overall_status;
  wrapper.dataset.formatRole = role;
  wrapper.dataset.checkedStatus = report.checked_status;
  const crypto = report.stage === 'm3_verification';
  const counts = report.summary.by_status;
  const state = report.checked_status === 'failed' ? (crypto ? '发现验证失败项' : '发现格式错误') : report.checked_status === 'passed' ? '已检查项通过' : report.checked_status === 'not_applicable' ? '未声明外置印章（不适用）' : '部分项目需复核';
  wrapper.append(element('p', `${crypto ? 'M3 验证' : '格式检查'}：${state}`, 'format-summary'),
    element('p', `通过 ${counts.passed} · 失败 ${counts.failed} · 无法确定 ${counts.indeterminate} · 跳过 ${counts.skipped} · 错误 ${counts.error} · 不适用 ${counts.not_applicable}`),
    element('p', crypto ? '已执行支持范围内的密码运算；证书信任、吊销和可信时间尚未完成，不能认定整体有效。' :
      '发现问题后继续独立检查；格式结果不包含密码验签，完整验证尚未完成。', 'muted'));
  if (crypto) wrapper.append(element('p', `验证时刻：${report.settings.verification_time}（本机时钟，非可信时间证据）`),
    element('p', `SM2 用户标识（十六进制）：${report.settings.sm2_id_hex}`));
  if (report.coverage?.limitations?.length) {
    const notes = element('div', undefined, 'format-coverage');
    notes.append(element('p', '检查能力说明：完整符合性尚未确认。以下是工具的覆盖范围，不是检测出的文件错误。'));
    for (const note of report.coverage.limitations) notes.append(element('p', note));
    wrapper.append(section('检查能力与未覆盖范围', notes));
  }
  const labels = new Map(report.planned_checks.map(item => [item.check_id, item.label]));
  const problems = element('ol', undefined, 'format-checks'), others = element('ol', undefined, 'format-checks');
  for (const check of report.checks) {
    const row = element('li'); row.dataset.checkStatus = check.status; row.dataset.checkId = check.check_id;
    row.append(element('strong', `${names[check.status] || check.status} · ${labels.get(check.check_id) || check.check_id}`),
      element('p', check.message), element('code', check.location || check.check_id));
    if (check.expected) row.append(element('p', `预期：${check.expected}`));
    if (check.actual) row.append(element('p', `实际：${check.actual}`));
    if (check.standard_reference) row.append(element('p', `依据：${check.standard_reference}`, 'muted'));
    if (check.remediation) row.append(element('p', check.remediation, 'muted'));
    (['passed', 'not_applicable'].includes(check.status) ? others : problems).append(row);
  }
  if (problems.children.length) wrapper.append(problems);
  wrapper.append(section('查看通过与不适用项目', others));
  return section(title, wrapper, true);
}

export function signaturePanel(viewer) {
  const panel = document.querySelector('#signature-panel');
  const button = document.querySelector('#signatures-toggle');
  const summary = document.querySelector('#signature-status');
  const select = document.querySelector('#signatures');
  const content = document.querySelector('#signature-content');
  let report = null, documentIndex = 0, highlights = [], currentFile = null, generation = 0;
  const controls = element('div', undefined, 'verification-controls');
  const uid = element('input'); uid.value = '1234567812345678'; uid.id = 'sm2-user-id'; uid.maxLength = 8191;
  const label = element('label', 'SM2 用户标识'); label.htmlFor = uid.id;
  const verifyButton = element('button', '执行 M3 验证'); verifyButton.id = 'verify-m3'; verifyButton.disabled = true;
  const verificationStatus = element('p', '', 'muted'); verificationStatus.setAttribute('role', 'status');
  controls.append(label, uid, verifyButton, verificationStatus); content.before(controls);
  verifyButton.addEventListener('click', async () => {
    if (!currentFile) return;
    const token = generation, file = currentFile;
    const idBytes = new TextEncoder().encode(uid.value);
    if (!idBytes.length || idBytes.length > 8191) { verificationStatus.textContent = 'SM2 用户标识需要 1–8191 字节。'; return; }
    verifyButton.disabled = true; verificationStatus.textContent = '正在执行 M3 验证，单项失败后继续检查…';
    try {
      const response = await fetch('verify', { method: 'POST', body: file, headers: { 'Content-Type': 'application/ofd',
        'X-Sealverify-SM2-ID': Array.from(idBytes, b => b.toString(16).padStart(2, '0')).join('') } });
      if (!response.ok) throw new Error(`本机验证服务返回 ${response.status}`);
      const result = await response.json();
      if (token !== generation) return;
      const selected = select.value;
      report = result; render();
      if ([...select.options].some(o => o.value === selected)) { select.value = selected; showSignature(); }
      verificationStatus.textContent = 'M3 检查结束；请查看逐项结果。完整验证仍未完成。';
    } catch (error) {
      if (token === generation) verificationStatus.textContent = `M3 验证未完成：${error.message}。可继续阅读并重试。`;
    } finally { if (token === generation) verifyButton.disabled = false; }
  });
  function clearHighlights() { highlights.forEach(node => node.remove()); highlights = []; }
  function locate(stamp, label) {
    clearHighlights();
    const page = viewer.getPageView(stamp.page_number);
    if (!page || !stamp.boundary_mm || !stamp.page_box_mm) return;
    const [x, y, w, h] = stamp.boundary_mm;
    const [px, py, pw, ph] = stamp.page_box_mm;
    const overlay = element('div', undefined, 'signature-highlight');
    overlay.setAttribute('aria-label', label);
    overlay.dataset.pageNumber = stamp.page_number;
    Object.assign(overlay.style, { left: `${(x - px) / pw * 100}%`, top: `${(y - py) / ph * 100}%`,
      width: `${w / pw * 100}%`, height: `${h / ph * 100}%` });
    // surface 未旋转：其现有变换会同时带动高亮，缩放无需重新计算毫米坐标。
    page.surface.append(overlay); highlights.push(overlay);
    viewer.goToPage(stamp.page_number, { smooth: false });
    overlay.scrollIntoView({ block: 'center', inline: 'nearest' });
  }
  function showSignature() {
    clearHighlights(); content.replaceChildren();
    const doc = report?.documents.find(item => item.index === documentIndex);
    const sig = doc?.signatures[Number(select.value)];
    if (!sig) return;
    const overview = element('div');
    const value = sig.signed_value;
    if (value?.seal?.picture?.preview) {
      const preview = element('img'); preview.src = value.seal.picture.preview;
      preview.alt = '当前印章预览（未验证）'; preview.className = 'seal-preview'; overview.append(preview);
    }
    overview.append(element('p', `签章 ID：${sig.id || '缺失'} · 类型：${sig.type || '未声明'}`),
      element('p', `结构解析：${sig.parse_status === 'parsed' ? '已读取' : '部分内容不可读'} · ${sig.m3_validation ? 'M3 已执行，完整验证未完成' : '密码验证：未执行'}`, 'muted'),
      element('p', `签章版本：${value?.version ?? '不可读'}`),
      element('p', `签章者：${value?.signer_certificate?.subject || '不可读'}`),
      element('p', `XML 声明时间：${sig.declared_time || '未声明'}`),
      element('p', `XML 算法：${sig.algorithm || '未声明'}`));
    const placements = element('div', undefined, 'signature-locations');
    for (const [index, stamp] of sig.placements.entries()) {
      const label = `定位第 ${stamp.page_number || '?'} 页 · 标记 ${index + 1}`;
      const link = element('button', label);
      link.disabled = !stamp.page_number || !stamp.boundary_mm || !stamp.page_box_mm;
      link.addEventListener('click', () => locate(stamp, label)); placements.append(link);
      placements.append(element('p', `页面 ID ${stamp.page_id || '?'}；位置（毫米）${stamp.boundary_mm?.join(', ') || '不可读'}${stamp.clip_mm ? '；裁剪 ' + stamp.clip_mm.join(', ') : ''}`));
    }
    if (!sig.placements.length) placements.append(element('p', '未提供可定位的 StampAnnot。'));
    content.append(overview, placements, formatSection(sig.format_validation));
    const seals = element('div');
    seals.append(element('p', '依据 GB/T 38540—2020 6.1、6.3 a)。本节仅检查格式；二者一致性与密码验签另见 M3 检查。', 'muted'),
      formatSection(sig.seal_format_validation?.embedded, '签章内嵌电子印章', 'embedded'),
      formatSection(sig.seal_format_validation?.external, 'OFD 外置电子印章', 'external'));
    content.append(section('第二步：电子印章数据格式验证', seals, true));
    if (sig.m3_validation) content.append(formatSection(sig.m3_validation, 'M3：密码验签、授权与原文杂凑', 'm3'));
    if (value) {
      const { seal, ...signature } = value;
      content.append(section('电子签章属性与签章者证书', tree(signature)));
      if (seal) content.append(sealSection('内嵌电子印章与制章者证书', seal));
    } else content.append(element('p', '签名值未能解析，请查看问题记录。', 'error'));
    if (sig.external_seal) content.append(sealSection('OFD 外置电子印章（独立资源）', sig.external_seal));
    const refs = element('div');
    refs.append(element('p', `共 ${sig.references.length} 条引用；杂凑方法：${sig.reference_method || '未声明'}。${sig.m3_validation ? '原始字节杂凑及绑定结果见 M3 明细；未引用内容不属于已核对范围。' : '未重算摘要，清单不代表完整保护范围。'}`));
    const list = element('ol');
    for (const ref of sig.references) {
      const row = element('li');
      row.append(element('p', ref.path || ref.declared_path),
        element('p', `${ref.present ? '目标存在' : '目标缺失或有歧义'} · ${sig.m3_validation ? '摘要核对结论见 M3 明细' : '未验证'}`),
        element('code', ref.check_value || '摘要缺失')); list.append(row);
    }
    refs.append(list); content.append(section('文件引用清单', refs));
    const paths = tree({ '签章 XML': sig.source_path, '签名值资源': sig.signed_value_path,
      '外置印章资源': sig.external_seal_path, '提供者': sig.provider });
    content.append(section('资源位置与提供者', paths));
    if (sig.issues.length) content.append(section('此签章的解析问题', issueList(sig.issues), true));
  }
  function sealSection(title, seal) {
    const wrapper = element('div');
    if (seal.picture?.preview) {
      const image = element('img'); image.src = seal.picture.preview;
      image.alt = '电子印章图像（未验证）'; image.className = 'seal-preview'; wrapper.append(image);
    }
    wrapper.append(tree(seal)); return section(title, wrapper);
  }
  function issueList(issues) {
    const list = element('ul', undefined, 'inspection-issues');
    for (const issue of issues) list.append(element('li', `${issue.location}：${issue.message}`));
    return list;
  }
  function render() {
    clearHighlights(); content.replaceChildren(); select.replaceChildren();
    const doc = report?.documents.find(item => item.index === documentIndex);
    const sigs = doc?.signatures || [];
    summary.textContent = doc ? `本份文档发现 ${sigs.length} 个签章 · ${report.m3_validation ? 'M3 已执行，完整验证未完成' : '均未验证'}${doc.issues.length ? ' · 解析不完整' : ''}` : '签章解析不可用；仍可阅读页面。';
    for (const [index, sig] of sigs.entries()) {
      const option = element('option', `${index + 1}. ${sig.signed_value?.seal?.property?.name || '签章 ' + (sig.id || '?')}`);
      option.value = index; select.append(option);
    }
    select.hidden = !sigs.length;
    showSignature();
    document.querySelector('#inspection-issues').replaceChildren();
    if (report?.issues.length) document.querySelector('#inspection-issues').append(section('包内解析问题', issueList(report.issues)));
  }
  select.addEventListener('change', showSignature);
  button.addEventListener('click', () => {
    panel.hidden = !panel.hidden;
    button.setAttribute('aria-expanded', String(!panel.hidden));
  });
  return {
    async load(file) {
      this.reset(); currentFile = file; const token = generation; summary.textContent = '正在读取签章属性…';
      button.disabled = false;
      try {
        const response = await fetch('inspect', { method: 'POST', headers: { 'Content-Type': 'application/ofd' }, body: file });
        if (!response.ok) throw new Error(`本机解析服务返回 ${response.status}`);
        const result = await response.json(); if (token !== generation) return;
        report = result; render(); verifyButton.disabled = false;
        if (report.documents.some(doc => doc.signatures.length) || report.issues.length) {
          panel.hidden = false; button.setAttribute('aria-expanded', 'true');
        }
      } catch (error) { if (token !== generation) return; summary.textContent = `签章解析失败：${error.message}。仍可阅读页面。`; panel.hidden = false; button.setAttribute('aria-expanded', 'true'); }
    },
    document(index) { documentIndex = index; render(); },
    reset() {
      generation++; currentFile = null; verifyButton.disabled = true; verificationStatus.textContent = '';
      report = null; documentIndex = 0; clearHighlights(); content.replaceChildren(); select.replaceChildren();
      document.querySelector('#inspection-issues').replaceChildren();
      panel.hidden = true; button.disabled = true; button.setAttribute('aria-expanded', 'false');
    },
  };
}
