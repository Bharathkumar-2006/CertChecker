"""
Certificate chain inspection module.
Fetches and displays the full certificate chain for a host.
"""

import ssl
import socket
from typing import List, Optional, Tuple
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


def get_certificate_chain(hostname: str, port: int = 443, timeout: int = 10) -> List[dict]:
    """
    Retrieve the full certificate chain for a host.
    Returns a list of dicts, ordered from leaf to root.
    """
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    chain_der = []

    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Get the DER-encoded cert chain
                pem_chain = ssock.get_verified_chain()
                if pem_chain:
                    chain_der = [cert for cert in pem_chain]
                else:
                    # Fallback: at least get the leaf
                    leaf_der = ssock.getpeercert(binary_form=True)
                    if leaf_der:
                        chain_der = [ssl.DER_cert_to_PEM_cert(leaf_der).encode()]
    except AttributeError:
        # get_verified_chain() not available in older Python
        context2 = ssl.create_default_context()
        context2.check_hostname = False
        context2.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context2.wrap_socket(sock, server_hostname=hostname) as ssock:
                    leaf_der = ssock.getpeercert(binary_form=True)
                    if leaf_der:
                        chain_der = [ssl.DER_cert_to_PEM_cert(leaf_der).encode()]
        except Exception:
            pass
    except Exception as e:
        raise RuntimeError(f"Could not fetch chain: {e}")

    result = []
    for i, cert_pem in enumerate(chain_der):
        try:
            if isinstance(cert_pem, memoryview):
                cert_pem = bytes(cert_pem)
            if isinstance(cert_pem, str):
                cert_pem = cert_pem.encode()

            # Try loading as PEM first
            try:
                parsed = x509.load_pem_x509_certificate(cert_pem, default_backend())
            except Exception:
                parsed = x509.load_der_x509_certificate(cert_pem, default_backend())

            result.append(_parse_chain_cert(parsed, position=i))
        except Exception as e:
            result.append({
                "position": i,
                "error": str(e),
                "subject": {},
                "issuer": {},
            })

    return result


def _parse_chain_cert(parsed: x509.Certificate, position: int) -> dict:
    """Extract chain-relevant info from a certificate."""
    now_utc = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)

    subject = _name_to_str(parsed.subject)
    issuer = _name_to_str(parsed.issuer)
    is_self_signed = parsed.subject == parsed.issuer
    is_ca = False
    try:
        bc = parsed.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bc.ca
    except x509.ExtensionNotFound:
        pass

    not_after = parsed.not_valid_after_utc
    days_remaining = (not_after - now_utc).days

    sha256_fp = parsed.fingerprint(hashes.SHA256()).hex(':').upper()

    roles = []
    if position == 0:
        roles.append("Leaf / End-Entity")
    if is_ca and not is_self_signed:
        roles.append("Intermediate CA")
    if is_self_signed and is_ca:
        roles.append("Root CA")

    return {
        "position": position,
        "role": " | ".join(roles) if roles else "Unknown",
        "subject_cn": subject.get("CN", subject.get("O", "Unknown")),
        "subject": subject,
        "issuer_cn": issuer.get("CN", issuer.get("O", "Unknown")),
        "issuer": issuer,
        "is_self_signed": is_self_signed,
        "is_ca": is_ca,
        "not_after": not_after.strftime("%Y-%m-%d"),
        "days_remaining": days_remaining,
        "sha256_fingerprint": sha256_fp,
    }


def _name_to_str(name: x509.Name) -> dict:
    oid_map = {
        "2.5.4.3": "CN",
        "2.5.4.6": "C",
        "2.5.4.7": "L",
        "2.5.4.8": "ST",
        "2.5.4.10": "O",
        "2.5.4.11": "OU",
    }
    result = {}
    for attr in name:
        key = oid_map.get(attr.oid.dotted_string, attr.oid.dotted_string)
        result[key] = attr.value
    return result
