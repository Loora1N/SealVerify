// 属性来自原始 OFD 的本机 Python 解析；不使用阅读副本进行签章检查。
const labels = {
  version: '版本', id: '标识', seal_id: '印章 ID', vendor: '厂商标识', type: '类型',
  name: '印章名称', created: '制作时间（声明）', valid_start: '有效期起', valid_end: '有效期止',
  cert_list_type: '授权证书列表类型', certificates: '印章授权证书', certificate_digests: '授权证书摘要',
  property: '印章属性', picture: '印章图像', width_mm: '宽度（毫米）', height_mm: '高度（毫米）',
  maker_certificate: '制章者证书', signer_certificate: '签章者证书', algorithm: '算法 OID',
  signature: '签名值', declared_time: '声明的签章时间（未验证）', data_hash: '声明的原文杂凑',
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
    list.append(element('dt', labels[key] || key));
    const cell = element('dd');
    cell.append(item && typeof item === 'object' && 'hex_preview' in item ? section(`${item.bytes} 字节 · 查看摘要`, tree(item)) : tree(item));
    list.append(cell);
  }
  if (!Object.keys(value).length) list.append(element('dd', '无'));
  return list;
}
function section(title, content, open = false) {
  const details = element('details', undefined, 'signature-section');
  details.open = open; details.append(element('summary', title), content); return details;
}

export function signaturePanel(viewer) {
  const panel = document.querySelector('#signature-panel');
  const button = document.querySelector('#signatures-toggle');
  const summary = document.querySelector('#signature-status');
  const select = document.querySelector('#signatures');
  const content = document.querySelector('#signature-content');
  let report = null, documentIndex = 0, highlights = [];
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
      element('p', `结构解析：${sig.parse_status === 'parsed' ? '已读取' : '部分内容不可读'} · 密码验证：未执行`, 'muted'),
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
    content.append(overview, placements);
    if (value) {
      const { seal, ...signature } = value;
      content.append(section('电子签章属性与签章者证书', tree(signature)));
      if (seal) content.append(sealSection('内嵌电子印章与制章者证书', seal));
    } else content.append(element('p', '签名值未能解析，请查看问题记录。', 'error'));
    if (sig.external_seal) content.append(sealSection('OFD 外置电子印章（独立资源）', sig.external_seal));
    const refs = element('div');
    refs.append(element('p', `共 ${sig.references.length} 条引用；杂凑方法：${sig.reference_method || '未声明'}。未重算摘要，清单不代表完整保护范围。`));
    const list = element('ol');
    for (const ref of sig.references) {
      const row = element('li');
      row.append(element('p', ref.path || ref.declared_path),
        element('p', `${ref.present ? '目标存在' : '目标缺失或有歧义'} · 未验证`),
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
    summary.textContent = doc ? `本份文档发现 ${sigs.length} 个签章 · 均未验证${doc.issues.length ? ' · 解析不完整' : ''}` : '签章解析不可用；仍可阅读页面。';
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
      this.reset(); summary.textContent = '正在读取签章属性…';
      button.disabled = false;
      try {
        const response = await fetch('inspect', { method: 'POST', headers: { 'Content-Type': 'application/ofd' }, body: file });
        if (!response.ok) throw new Error(`本机解析服务返回 ${response.status}`);
        report = await response.json(); render();
        if (report.documents.some(doc => doc.signatures.length) || report.issues.length) {
          panel.hidden = false; button.setAttribute('aria-expanded', 'true');
        }
      } catch (error) { summary.textContent = `签章解析失败：${error.message}。仍可阅读页面。`; panel.hidden = false; button.setAttribute('aria-expanded', 'true'); }
    },
    document(index) { documentIndex = index; render(); },
    reset() {
      report = null; documentIndex = 0; clearHighlights(); content.replaceChildren(); select.replaceChildren();
      document.querySelector('#inspection-issues').replaceChildren();
      panel.hidden = true; button.disabled = true; button.setAttribute('aria-expanded', 'false');
    },
  };
}
