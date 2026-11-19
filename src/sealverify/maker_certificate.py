"""GB/T 38540—2020 6.3 c)、7.3 e) 的制章者和签章者证书诊断。"""

import hashlib
from datetime import timezone

from OpenSSL import crypto
from asn1crypto.crl import CertificateList
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtensionOID, ExtendedKeyUsageOID

from .crypto import DEFAULT_SM2_ID, verify_signature
from .inspection.asn1 import SM2_SM3
from .results import CheckResult, CheckSpec, CheckStatus, VerificationReport


LIMITS = {'anchor': 128 * 1024, 'intermediate': 128 * 1024, 'crl': 1024 * 1024}
MAX_MATERIAL_BYTES = 4 * 1024 * 1024
MAX_MATERIAL_FILES = 32


class Uncertain(Exception):
    """缺少充分证据，不能判定文件错误。"""


class Rejected(Exception):
    """已有证据能确认检查失败。"""


class ExpiredOrRevoked(Rejected):
    """叶证书当前过期或已被吊销。签章者遇此结果时需依据 7.3 f) 复核。"""


def extension(obj, oid):
    try:
        return obj.extensions.get_extension_for_oid(oid).value
    except x509.ExtensionNotFound:
        return None


def read_material(role, raw):
    if not raw or len(raw) > LIMITS[role]:
        raise ValueError('材料为空或超过大小上限')
    is_crl = role == 'crl'
    pem = raw.lstrip().startswith(b'-----BEGIN')
    if pem:
        label = b'X509 CRL' if is_crl else b'CERTIFICATE'
        if (raw.count(b'-----BEGIN') != 1 or not raw.strip().startswith(b'-----BEGIN ' + label + b'-----')
                or not raw.strip().endswith(b'-----END ' + label + b'-----')):
            raise ValueError('请每份文件只提供一个对应类型的 PEM 对象')
        load = x509.load_pem_x509_crl if is_crl else x509.load_pem_x509_certificate
    else:
        load = x509.load_der_x509_crl if is_crl else x509.load_der_x509_certificate
    value = load(raw)
    if not pem and value.public_bytes(Encoding.DER) != raw:
        raise ValueError('DER 文件须只包含一个完整对象')
    if not is_crl:
        bc = extension(value, ExtensionOID.BASIC_CONSTRAINTS)
        if bc is None or not bc.ca:
            raise ValueError('此材料没有声明 CA 身份')
    return value


class Materials:
    """每次验证重新建立，只信任显式选择为 anchor 的 CA。"""

    def __init__(self, entries=()):
        self.anchors, self.intermediates, self.crls = [], [], []
        self.inventory = []
        groups = {'anchor': self.anchors, 'intermediate': self.intermediates, 'crl': self.crls}
        seen = set()
        total = 0
        for index, (role, raw) in enumerate(entries):
            if index >= MAX_MATERIAL_FILES or role not in groups:
                raise ValueError('验证材料角色无效或超过 32 份')
            total += len(raw)
            if total > MAX_MATERIAL_BYTES:
                raise ValueError('验证材料总量超过 4 MiB')
            record = {'role': role, 'index': index + 1, 'sha256': hashlib.sha256(raw).hexdigest()}
            try:
                value = read_material(role, raw)
                key = (role, value.fingerprint(hashes.SHA256()))
                if key not in seen:
                    groups[role].append(value)
                    seen.add(key)
                record['status'] = 'loaded'
            except (ValueError, UnsupportedAlgorithm, x509.DuplicateExtension, x509.UnsupportedGeneralNameType) as exc:
                record.update(status='unavailable', message='无法加载为指定类型的材料。' + str(exc)[:120])
            self.inventory.append(record)

    def chain(self, cert, at):
        if not self.anchors:
            raise Uncertain('缺少明确选择的 CA 信任锚，请补充信任材料。')
        store = crypto.X509Store()
        store.set_time(at.astimezone(timezone.utc))
        flags = crypto.X509StoreFlags
        store.set_flags(flags.X509_STRICT | flags.POLICY_CHECK | flags.PARTIAL_CHAIN)
        for anchor in self.anchors:
            store.add_cert(crypto.X509.from_cryptography(anchor))
        ctx = crypto.X509StoreContext(store, crypto.X509.from_cryptography(cert),
                                      [crypto.X509.from_cryptography(c) for c in self.intermediates])
        try:
            return [v.to_cryptography() for v in ctx.get_verified_chain()]
        except crypto.X509StoreContextError as exc:
            code, depth, reason = exc.errors
            detail = f'路径深度 {depth}，OpenSSL {code}（{reason}）。'
            if code in (2, 18, 19, 20, 21):
                raise Uncertain('无法连接所选信任锚，请补充对应的中间 CA 或信任锚。' + detail) from exc
            if code == 10 and depth == 0:
                raise ExpiredOrRevoked('路径中的被检证书已过期。' + detail) from exc
            # 未知算法、后端错误等没有足够证据指认文件无效。
            if code in (9, 10, 25, 32, 37, 47, 48, 79):
                raise Rejected('证书路径未满足有效期或 CA 约束。' + detail) from exc
            if code == 7 and exc.certificate.to_cryptography().signature_algorithm_oid.dotted_string in (
                    '1.2.840.113549.1.1.11', '1.2.840.10045.4.3.2'):
                raise Rejected('证书颁发者签名验证失败。' + detail) from exc
            raise Uncertain('在当前材料及算法配置下无法确认路径。' + detail) from exc


def validity(cert, at):
    start, end = cert.not_valid_before_utc, cert.not_valid_after_utc
    period = f'{start.isoformat()} 至 {end.isoformat()}'
    if at > end:
        raise ExpiredOrRevoked('验证时刻证书已过期。有效期为 ' + period)
    if at < start:
        raise Rejected('验证时刻证书尚未生效。有效期为 ' + period)
    return '验证时刻位于证书有效期内。有效期为 ' + period


def key_usage(cert):
    ku = extension(cert, ExtensionOID.KEY_USAGE)
    if ku is None:
        raise Uncertain('证书未声明 KeyUsage，需结合证书策略复核签名用途。')
    if not (ku.digital_signature or ku.content_commitment):
        raise Rejected('KeyUsage 同时缺少 digitalSignature 和 contentCommitment。')
    eku = extension(cert, ExtensionOID.EXTENDED_KEY_USAGE)
    if eku is not None and ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in eku:
        raise Uncertain('签名用途位已设置，需依据业务配置确认专用 EKU 允许此用途。')
    return 'KeyUsage 允许签名：' + '、'.join(name for name, enabled in (
        ('digitalSignature', ku.digital_signature), ('contentCommitment', ku.content_commitment)) if enabled)


def verify_crl_signature(crl, issuer):
    obj = CertificateList.load(crl.public_bytes(Encoding.DER), strict=True)
    algorithm = obj['signature_algorithm']
    if algorithm.dump() != obj['tbs_cert_list']['signature'].dump():
        raise Uncertain('CRL 内外签名算法声明不一致。')
    if crl.signature_algorithm_oid.dotted_string == SM2_SM3:
        if algorithm['parameters'].dump() not in (b'', b'\x05\x00'):
            raise Uncertain('未支持此 SM2 CRL 的签名算法参数。')
        try:
            verify_signature(issuer.public_bytes(Encoding.DER), SM2_SM3,
                             crl.tbs_certlist_bytes, crl.signature, DEFAULT_SM2_ID)
        except ValueError as exc:
            raise Uncertain('使用标准用户标识验证 SM2 CRL 未通过。') from exc
    elif not crl.is_signature_valid(issuer.public_key()):
        raise Uncertain('CRL 签名未通过，无法据此判定证书吊销状态。')


def revocation(cert, chain, materials, at):
    if not materials.crls:
        raise Uncertain('缺少可读取的 CRL，请补充颁发者发布的完整 CRL。')
    if len(chain) >= 2:
        issuer = chain[1]
    else:
        # 即使叶证书已过期，也可以独立认证颁发者和 CRL。
        issuers = []
        for candidate in materials.intermediates + materials.anchors:
            if candidate == cert or candidate.subject != cert.issuer or candidate in issuers:
                continue
            try:
                issuer_usage = extension(candidate, ExtensionOID.KEY_USAGE)
                if issuer_usage is None or not issuer_usage.key_cert_sign:
                    continue
                cert.verify_directly_issued_by(candidate)
                materials.chain(candidate, at)
                issuers.append(candidate)
            except (Uncertain, Rejected, InvalidSignature, UnsupportedAlgorithm, ValueError, TypeError,
                    x509.DuplicateExtension, x509.UnsupportedGeneralNameType):
                continue
        if len(issuers) != 1:
            raise Uncertain('尚无可唯一认证的颁发者，无法认证 CRL。')
        issuer = issuers[0]
    applicable = [v for v in materials.crls if v.issuer == issuer.subject]
    if len(applicable) != 1:
        raise Uncertain('需要一份可唯一确定、由该颁发者签发的完整 CRL。请核对所选材料。')
    crl = applicable[0]
    if (extension(cert, ExtensionOID.FRESHEST_CRL) is not None or
            any(e.critical or e.oid not in (ExtensionOID.AUTHORITY_KEY_IDENTIFIER, ExtensionOID.CRL_NUMBER)
                for e in crl.extensions)):
        raise Uncertain('CRL 扩展或增量配置超出直接、完整 CRL 的支持范围。')
    dps = extension(cert, ExtensionOID.CRL_DISTRIBUTION_POINTS)
    if dps and any(dp.crl_issuer or dp.reasons or dp.relative_name for dp in dps):
        raise Uncertain('证书声明了间接或受限分发点，需复核 CRL 适用范围。')
    ku = extension(issuer, ExtensionOID.KEY_USAGE)
    if ku is None or not ku.crl_sign:
        raise Uncertain('颁发者未明确声明 cRLSign，无法确认清单签发权限。')
    aki = extension(crl, ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
    ski = extension(issuer, ExtensionOID.SUBJECT_KEY_IDENTIFIER)
    if (aki is None or ski is None or aki.key_identifier != ski.digest or
            aki.authority_cert_issuer is not None or aki.authority_cert_serial_number is not None):
        raise Uncertain('无法用已支持的密钥标识配置确认 CRL 颁发者。')
    verify_crl_signature(crl, issuer)
    if not crl.next_update_utc or not crl.last_update_utc <= at < crl.next_update_utc:
        raise Uncertain('CRL 缺少 nextUpdate 或在本次验证时刻不可用。')
    if len(crl) > 10000:
        raise Uncertain('CRL 超过 10000 个条目的检查限额。')
    revoked_at = None
    for entry in crl:
        for ext in entry.extensions:
            if ext.critical or isinstance(ext.value, x509.CertificateIssuer):
                raise Uncertain('吊销条目含间接颁发者或关键扩展，无法确认直接 CRL 的语义。')
            if isinstance(ext.value, x509.CRLReason) and ext.value.reason == x509.ReasonFlags.remove_from_crl:
                raise Uncertain('清单含增量 CRL 的移除原因，需复核完整清单。')
        if entry.serial_number == cert.serial_number:
            if entry.revocation_date_utc > at:
                raise Uncertain('匹配的吊销条目时间晚于验证时刻，需复核清单。')
            revoked_at = entry.revocation_date_utc
    if revoked_at is not None:
        raise ExpiredOrRevoked('经验证的 CRL 已列出该证书的序列号，清单记载的撤销时间为 ' + revoked_at.isoformat() + '。')
    return '已验证颁发者、CRL 签名、范围及更新时间。所提供完整清单中未列出此证书。'


def check_maker(raw, materials, at, location, object_id, *, absent=False):
    return check_certificate(raw, materials, at, location, object_id, signer=False, absent=absent)


def check_certificate(raw, materials, at, location, object_id, *, signer, absent=False):
    results, plan = [], []
    chain = []
    review_checks = []
    role = '签章者' if signer else '制章者'
    reference = 'GB/T 38540—2020 ' + ('7.3 e)' if signer else '6.3 c)') + '；RFC 5280'
    def check_path():
        if cert in materials.anchors:
            raise Uncertain(role + '证书本身被选为信任锚，无法独立确认颁发者。')
        chain.extend(materials.chain(cert, at))
        return '已验证 %d 张证书，终点为所选 CA。' % len(chain)

    cert = None
    reason = role + '证书原始字段不可读取。'
    if raw is not None:
        try:
            if len(raw) > 64 * 1024:
                raise Uncertain('证书超过 64 KiB 检查限额。')
            cert = x509.load_der_x509_certificate(raw)
        except (Uncertain, ValueError, UnsupportedAlgorithm) as exc:
            reason = '证书解码未完成。' + str(exc)[:120]
    operations = (('validity', '证书有效期', lambda: validity(cert, at)),
                  ('key_usage', '签章签名密钥用法' if signer else '制章签名密钥用法', lambda: key_usage(cert)),
                  ('path', '至选定信任锚的证书路径', check_path),
                  ('revocation', role + '证书吊销状态', lambda: revocation(cert, chain, materials, at)))
    for key, label, operation in operations:
        plan.append(CheckSpec(object_id, key, label))
        if absent:
            status, message = 'not_applicable', 'OFD 未声明外置印章。'
        elif cert is None:
            status, message = 'skipped', reason
        else:
            try:
                message = operation()
                status = 'passed'
            except Rejected as exc:
                status, message = 'failed', str(exc)
                if signer and isinstance(exc, ExpiredOrRevoked):
                    review_checks.append(key)
                    message += ' 需按 7.3 f) 复核签章时刻的状态。'
            except (Uncertain, UnsupportedAlgorithm, ValueError, x509.DuplicateExtension, x509.UnsupportedGeneralNameType) as exc:
                status, message = 'indeterminate', str(exc)[:300] or '该算法或证书配置需复核。'
            except Exception as exc:
                status, message = 'error', '检查器异常：' + type(exc).__name__
        results.append(CheckResult(object_id, key, CheckStatus(status), message,
                       location=location, standard_reference=reference))
    report = VerificationReport(location, tuple(plan), tuple(results), generated_at=at).to_dict()
    report.update(checked_status='not_applicable' if absent else report['overall_status'],
                  verification_time=at.isoformat(), chain_sha256=[c.fingerprint(hashes.SHA256()).hex() for c in chain],
                  certificate_sha256=hashlib.sha256(raw).hexdigest() if raw is not None else None)
    if signer:
        report['signing_time_review_checks'] = review_checks
        report['definitive_failure'] = any(
            row.status == CheckStatus.FAILED and row.check_id not in review_checks for row in results)
    return report
