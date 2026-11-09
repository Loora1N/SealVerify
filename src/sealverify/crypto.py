"""M3 密码运算适配：只验签，不建立证书信任，不处理私钥。"""

import hashlib

from asn1crypto import core, x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
import gmalg
from gmalg.errors import GMError

from .inspection.asn1 import SM2_SM3, bits, scalar, sequence
from .inspection.format import der_tree, LimitError


DEFAULT_SM2_ID = b'1234567812345678'
SM2_P = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', 16)
SM2_N = int('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', 16)
RSA_HASHES = {'1.2.840.113549.1.1.' + suffix: name for suffix, name in
              [('5', 'sha1'), ('11', 'sha256'), ('12', 'sha384'), ('13', 'sha512'), ('14', 'sha224')]}
HASH_NAMES = {'SM3': 'sm3', '1.2.156.10197.1.401': 'sm3',
              'SHA1': 'sha1', 'SHA-1': 'sha1', '1.3.14.3.2.26': 'sha1'}
for suffix, name in [('1', 'sha256'), ('2', 'sha384'), ('3', 'sha512'), ('4', 'sha224')]:
    HASH_NAMES[name.upper()] = name
    HASH_NAMES[name.upper().replace('SHA', 'SHA-')] = name
    HASH_NAMES['2.16.840.1.101.3.4.2.' + suffix] = name


def hash_name(declaration):
    name = HASH_NAMES.get((declaration or '').upper())
    if name is None:
        raise LimitError('未支持或未声明的杂凑算法；没有按摘要长度猜测算法')
    return name


def digest(data, name):
    if name not in {'sm3', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'}:
        raise LimitError('未支持的杂凑算法')
    try:
        return hashlib.new(name, data).digest()
    except ValueError:
        if name != 'sm3':
            raise LimitError('本机未提供所需杂凑算法') from None
        h = gmalg.SM3()
        h.update(data)
        return h.value()


def signature_hash(oid):
    if oid == SM2_SM3:
        return 'sm3'
    if oid in RSA_HASHES:
        return RSA_HASHES[oid]
    raise LimitError('无法由已支持的签名算法确定原文杂凑算法；不猜测 PSS 参数')


def certificate(data):
    if len(data) > 64 * 1024:
        raise LimitError('证书超过 64 KiB 检查上限')
    der_tree(data)
    value = x509.Certificate.load(data, strict=True)
    # 强制访问必要字段，防止只有外层可读就进入密码运算。
    tbs = value['tbs_certificate']
    tbs['subject'].native
    tbs['issuer'].native
    tbs['serial_number'].native
    tbs['validity'].native
    return value


def verify_signature(cert_der, oid, message, signature, sm2_id=DEFAULT_SM2_ID):
    """验证原始 DER 待签名区；异常区分不支持和实际失败。"""
    if len(message) > 16 * 1024 * 1024 or len(signature) > 64 * 1024:
        raise LimitError('密码验证输入超过实现限额')
    der_tree(message)
    cert = certificate(cert_der)
    spki = cert['tbs_certificate']['subject_public_key_info']
    key_oid = spki['algorithm']['algorithm'].dotted
    if oid == SM2_SM3:
        if not 1 <= len(sm2_id) <= 8191:
            raise ValueError('SM2 用户标识需要 1–8191 字节')
        if key_oid == '1.2.840.10045.2.1':
            params = spki['algorithm']['parameters']
            if params.name != 'named':
                raise LimitError('未支持 SM2 显式或隐式曲线参数')
            if core.ObjectIdentifier.load(params.dump()).dotted != '1.2.156.10197.1.301':
                raise ValueError('证书公钥不是 SM2 命名曲线')
        elif key_oid != '1.2.156.10197.1.301':
            raise ValueError('SM2 签名与主体公钥算法不匹配')
        point = bits(list(der_tree(spki.dump()).children())[1])
        if len(point) != 65 or point[0] != 4:
            raise LimitError('仅支持 65 字节未压缩 SM2 公钥点')
        if any(int.from_bytes(v, 'big') >= SM2_P for v in (point[1:33], point[33:])):
            raise ValueError('SM2 公钥坐标超出素域')
        try:
            verifier = gmalg.SM2(pk=point, uid=sm2_id)
            if not verifier.verify_pk(point):
                raise ValueError('SM2 公钥点不在曲线上、为无穷远点或阶不正确')
            parts = sequence(der_tree(signature), 2, 2)
            r, s = [scalar(n, core.Integer) for n in parts]
            if not (1 <= r < SM2_N and 1 <= s < SM2_N):
                raise ValueError('SM2 r/s 不在 [1, n−1] 范围')
            valid = verifier.verify(message, r.to_bytes(32, 'big'), s.to_bytes(32, 'big'))
        except GMError:
            raise ValueError('SM2 公钥或签名数据无效') from None
    elif oid in RSA_HASHES:
        if key_oid != '1.2.840.113549.1.1.1':
            raise ValueError('RSA PKCS #1 v1.5 签名与主体公钥声明不匹配')
        try:
            key = serialization.load_der_public_key(spki.dump())
        except UnsupportedAlgorithm:
            raise LimitError('密码后端不支持该 RSA 公钥') from None
        if not isinstance(key, rsa.RSAPublicKey):
            raise ValueError('证书中不是 RSA 公钥')
        if key.key_size > 16384:
            raise LimitError('RSA 公钥超过 16384 位实现上限')
        if len(signature) != (key.key_size + 7) // 8:
            raise ValueError('RSA 签名长度不等于模数字节数')
        algorithm = getattr(hashes, RSA_HASHES[oid].upper())()
        try:
            key.verify(signature, message, padding.PKCS1v15(), algorithm)
            valid = True
        except InvalidSignature:
            valid = False
    else:
        raise LimitError('未支持的签名算法；PSS 的 OID 不携带完整参数，不猜测盐长或杂凑算法')
    if not valid:
        raise ValueError('签名数学验证失败：签名、公钥、待签名字节或 SM2 用户标识不匹配')
    return True
