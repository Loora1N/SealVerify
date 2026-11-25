"""生成真实数学签名的合成 OFD；临时私钥只在内存，证书不受信任。"""

import argparse
from io import BytesIO
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED
from xml.sax.saxutils import escape

from asn1crypto import x509, keys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import gmalg

from sealverify.crypto import DEFAULT_SM2_ID, digest
try:
    from .create_signed_demo import build_signed_demo, signature, certificate, CertList, DigestList, IntegerPair
except ImportError:
    from create_signed_demo import build_signed_demo, signature, certificate, CertList, DigestList, IntegerPair


def identity(name, algorithm, uid):
    cert = x509.Certificate.load(certificate(name))
    if algorithm == 'sm2':
        secret, public = gmalg.SM2().generate_keypair()
        signer = gmalg.SM2(sk=secret, pk=public, uid=uid)
        spki = keys.PublicKeyInfo({'algorithm': {'algorithm': 'ec', 'parameters':
            keys.ECDomainParameters(name='named', value='1.2.156.10197.1.301')}, 'public_key': public})
        def sign(message):
            r, s = signer.sign(message)
            return IntegerPair({'r': int.from_bytes(r, 'big'), 's': int.from_bytes(s, 'big')}).dump()
        oid, hash_alg = '1.2.156.10197.1.501', 'sm3'
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        spki = keys.PublicKeyInfo.load(key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo))
        def sign(message):
            return key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        oid, hash_alg = '1.2.840.113549.1.1.11', 'sha256'
    cert['tbs_certificate']['subject_public_key_info'] = spki
    return cert.dump(), sign, oid, hash_alg


def build_verified_demo(*, algorithm='sm2', digest_list=False, tampered=False, sm2_id=DEFAULT_SM2_ID):
    with ZipFile(BytesIO(build_signed_demo(format_errors=True))) as z:
        entries = {n: z.read(n) for n in z.namelist()}
    targets = sorted(n for n in entries if '/Signs/' not in n)
    for index in range(2):
        base = 'Doc_0/Signs/Sign_%s/' % index
        value = signature(index + 1)
        signer_cert, sign, oid, name = identity('M3 synthetic signer %s - NOT TRUSTED' % index, algorithm, sm2_id)
        maker_cert, make, _, _ = identity('M3 synthetic maker - NOT TRUSTED', algorithm, sm2_id)
        value['cert'], value['algorithm'] = signer_cert, oid
        seal = value['tbs']['seal']; seal['cert'], seal['algorithm'] = maker_cert, oid
        props = seal['info']['property']
        props['cert_type'] = 2 if digest_list else 1
        props['certs'] = DigestList([{'type': name.upper(), 'value': digest(signer_cert, name)}]) if digest_list else CertList([signer_cert])
        seal['signature'] = make(seal['info'].dump())
        entries[base + 'Seal.esl'] = seal.dump()
        import base64
        refs = ''.join('<ofd:Reference FileRef="/%s"><ofd:CheckValue>%s</ofd:CheckValue></ofd:Reference>' %
                       (escape(n, {'"': '&quot;'}), base64.b64encode(digest(entries[n], name)).decode()) for n in targets)
        xml = entries[base + 'Signature.xml'].decode('utf-8')
        start, end = xml.index('<ofd:References'), xml.index('</ofd:References>') + len('</ofd:References>')
        xml = xml[:start] + '<ofd:References CheckMethod="%s">%s</ofd:References>' % (name.upper(), refs) + xml[end:]
        xml = xml.replace('1.2.156.10197.1.501', oid)
        entries[base + 'Signature.xml'] = xml.encode('utf-8')
        value['tbs']['property'] = '/' + base + 'Signature.xml'
        value['tbs']['hash'] = digest(entries[base + 'Signature.xml'], name)
        value['signature'] = sign(value['tbs'].dump())
        entries[base + 'SignedValue.dat'] = value.dump()
    if tampered:
        entries['Doc_0/Pages/Page_0/Content.xml'] += b'\n<!-- synthetic tamper -->'
    out = BytesIO()
    with ZipFile(out, 'w', ZIP_DEFLATED) as z:
        for name, data in entries.items():
            z.writestr(name, data)
    return out.getvalue()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output', type=Path)
    parser.add_argument('--algorithm', choices=['sm2', 'rsa'], default='sm2')
    parser.add_argument('--digest-list', action='store_true')
    parser.add_argument('--tampered', action='store_true')
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(build_verified_demo(algorithm=args.algorithm, digest_list=args.digest_list, tampered=args.tampered))
    print('已生成真实数学签名的合成样例；私钥未写盘，证书不可信，不能作为整体有效签章。')
