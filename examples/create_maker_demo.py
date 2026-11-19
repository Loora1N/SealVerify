"""生成仅用于本地演示的制章者证书链、两个 CRL 和带签名的 OFD。"""

import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

try:
    from .create_verified_demo import build_verified_demo
except ImportError:
    from create_verified_demo import build_verified_demo


def issue(label, at, *, issuer=None, ca=False, signing=True, expired=False, eku=None):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'SealVerify demo ' + label)])
    issuer_name, issuer_key = (issuer[0].subject, issuer[1]) if issuer else (name, key)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(at - timedelta(days=5))
               .not_valid_after(at + timedelta(days=-1 if expired else 30))
               .add_extension(x509.BasicConstraints(ca, None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
    if signing is not None:
        usage = x509.KeyUsage(signing and not ca, False, not signing, False, False, ca, ca, False, False)
        builder = builder.add_extension(usage, critical=True)
    if eku:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku), critical=False)
    return builder.sign(issuer_key, hashes.SHA256()), key


def make_crl(issuer, at, *, revoked=None, stale=False, sign_with=None, extra=None):
    cert, key = issuer
    builder = (x509.CertificateRevocationListBuilder().issuer_name(cert.subject)
               .last_update(at - timedelta(days=2)).next_update(at + timedelta(days=-1 if stale else 7))
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
               .add_extension(x509.CRLNumber(2 if revoked is not None else 1), critical=False))
    if revoked is not None:
        entry = x509.RevokedCertificateBuilder().serial_number(revoked.serial_number).revocation_date(at - timedelta(days=1))
        builder = builder.add_revoked_certificate(entry.build())
    if extra is not None:
        builder = builder.add_extension(extra, critical=True)
    return builder.sign(sign_with or key, hashes.SHA256())


def create(directory):
    directory.mkdir(parents=True, exist_ok=True)
    now = datetime.now(timezone.utc)
    root = issue('root', now, ca=True)
    intermediate = issue('issuing CA', now, issuer=root, ca=True)
    maker, key = issue('maker', now, issuer=intermediate)
    files = {'anchor.cer': root[0], 'intermediate.cer': intermediate[0], 'current.crl': make_crl(intermediate, now),
             'revoked.crl': make_crl(intermediate, now, revoked=maker)}
    for name, obj in files.items():
        (directory / name).write_bytes(obj.public_bytes(serialization.Encoding.DER))
    def sign(data):
        return key.sign(data, padding.PKCS1v15(), hashes.SHA256())
    maker_identity = (maker.public_bytes(serialization.Encoding.DER), sign, '1.2.840.113549.1.1.11', 'sha256')
    (directory / 'maker.ofd').write_bytes(build_verified_demo(algorithm='rsa', maker_identity=maker_identity))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    create(parser.parse_args().directory)
