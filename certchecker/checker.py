"""
Core SSL certificate inspection engine.
Handles socket connections, certificate parsing, and analysis.
"""

import ssl
import socket
import datetime
from typing import Optional, Any
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
import ipaddress


class CertCheckError(Exception):
    """Raised when a certificate check fails."""
    pass


def get_certificate(hostname: str, port: int = 443, timeout: int = 10) -> dict:
    """
    Connect to a host and retrieve SSL certificate information.
    Returns a rich dict of parsed certificate data.
    """
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    raw_cert_der = None
    cert_dict = {}
    negotiated_cipher = None
    tls_version = None
    resolved_ip = None

    # Resolve IP
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        resolved_ip = "Unable to resolve"

    # Attempt verified connection
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                raw_cert_der = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()
                negotiated_cipher = ssock.cipher()
                tls_version = ssock.version()
    except ssl.SSLCertVerificationError as e:
        # Try unverified to still get cert info for analysis
        unverified_ctx = ssl.create_default_context()
        unverified_ctx.check_hostname = False
        unverified_ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with unverified_ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    raw_cert_der = ssock.getpeercert(binary_form=True)
                    cert_dict = ssock.getpeercert(binary_form=False) or {}
                    negotiated_cipher = ssock.cipher()
                    tls_version = ssock.version()
        except Exception as inner_e:
            raise CertCheckError(f"SSL verification failed and fallback failed: {inner_e}") from e
        # Mark as verification failure but continue
        cert_dict["_verification_error"] = str(e)
    except ssl.SSLError as e:
        raise CertCheckError(f"SSL error: {e}") from e
    except socket.timeout:
        raise CertCheckError(f"Connection timed out after {timeout}s")
    except ConnectionRefusedError:
        raise CertCheckError(f"Connection refused on port {port}")
    except OSError as e:
        raise CertCheckError(f"Network error: {e}") from e

    if not raw_cert_der:
        raise CertCheckError("Could not retrieve certificate")

    # Parse with cryptography library for deep inspection
    parsed = x509.load_der_x509_certificate(raw_cert_der, default_backend())

    result = _build_result(
        hostname=hostname,
        port=port,
        cert_dict=cert_dict,
        parsed=parsed,
        negotiated_cipher=negotiated_cipher,
        tls_version=tls_version,
        resolved_ip=resolved_ip,
    )

    return result


def _build_result(
    hostname: str,
    port: int,
    cert_dict: dict,
    parsed: x509.Certificate,
    negotiated_cipher: Optional[tuple],
    tls_version: Optional[str],
    resolved_ip: Optional[str],
) -> dict:
    """Build a comprehensive result dictionary from parsed certificate data."""
    now = datetime.datetime.now(datetime.timezone.utc)

    # Validity dates
    not_before = parsed.not_valid_before_utc
    not_after = parsed.not_valid_after_utc
    days_remaining = (not_after - now).days
    is_expired = now > not_after
    is_not_yet_valid = now < not_before

    # Subject / Issuer
    subject = _name_to_dict(parsed.subject)
    issuer = _name_to_dict(parsed.issuer)

    # Self-signed detection
    is_self_signed = (
        parsed.subject == parsed.issuer
    )

    # SANs
    sans = []
    try:
        san_ext = parsed.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(n) for n in san_ext.value]
    except x509.ExtensionNotFound:
        pass

    # Key info
    pub_key = parsed.public_key()
    key_info = _get_key_info(pub_key)

    # Signature algorithm
    sig_algo = parsed.signature_hash_algorithm
    sig_algo_name = sig_algo.name.upper() if sig_algo else "Unknown"
    is_weak_sig = sig_algo_name in ("SHA1", "MD5", "MD2")

    # Serial number
    serial = format(parsed.serial_number, 'X')

    # Fingerprints
    sha1_fp = parsed.fingerprint(hashes.SHA1()).hex(':').upper()
    sha256_fp = parsed.fingerprint(hashes.SHA256()).hex(':').upper()

    # Key usage
    key_usage = _get_key_usage(parsed)

    # Extended key usage
    ext_key_usage = _get_ext_key_usage(parsed)

    # OCSP / CRL
    ocsp_urls = _get_ocsp_urls(parsed)
    crl_urls = _get_crl_urls(parsed)

    # Basic constraints
    is_ca = _is_ca(parsed)

    # Verification error
    verification_error = cert_dict.get("_verification_error")

    # Weakness flags
    weaknesses = []
    if is_weak_sig:
        weaknesses.append(f"Weak signature algorithm: {sig_algo_name}")
    if is_self_signed:
        weaknesses.append("Certificate is self-signed")
    if key_info.get("bits") and key_info["bits"] < 2048:
        weaknesses.append(f"Weak key size: {key_info['bits']} bits (recommend ≥ 2048)")
    if is_expired:
        weaknesses.append("Certificate has EXPIRED")
    if verification_error:
        weaknesses.append(f"Verification failed: {verification_error}")

    return {
        "hostname": hostname,
        "port": port,
        "resolved_ip": resolved_ip,
        "tls_version": tls_version,
        "cipher_suite": negotiated_cipher[0] if negotiated_cipher else None,
        "cipher_bits": negotiated_cipher[2] if negotiated_cipher else None,

        # Validity
        "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "days_remaining": days_remaining,
        "is_expired": is_expired,
        "is_not_yet_valid": is_not_yet_valid,
        "is_valid": not is_expired and not is_not_yet_valid and not verification_error,

        # Identity
        "subject": subject,
        "issuer": issuer,
        "is_self_signed": is_self_signed,
        "is_ca": is_ca,
        "serial_number": serial,

        # SANs
        "sans": sans,

        # Key
        "key_type": key_info.get("type"),
        "key_bits": key_info.get("bits"),
        "key_curve": key_info.get("curve"),

        # Signature
        "signature_algorithm": sig_algo_name,
        "is_weak_signature": is_weak_sig,

        # Fingerprints
        "fingerprint_sha1": sha1_fp,
        "fingerprint_sha256": sha256_fp,

        # Extensions
        "key_usage": key_usage,
        "extended_key_usage": ext_key_usage,
        "ocsp_urls": ocsp_urls,
        "crl_urls": crl_urls,

        # Analysis
        "weaknesses": weaknesses,
        "verification_error": verification_error,
        "checked_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def _name_to_dict(name: x509.Name) -> dict:
    """Convert an x509 Name to a flat dictionary."""
    result = {}
    oid_map = {
        "2.5.4.3": "CN",
        "2.5.4.6": "C",
        "2.5.4.7": "L",
        "2.5.4.8": "ST",
        "2.5.4.10": "O",
        "2.5.4.11": "OU",
        "1.2.840.113549.1.9.1": "emailAddress",
    }
    for attr in name:
        key = oid_map.get(attr.oid.dotted_string, attr.oid.dotted_string)
        result[key] = attr.value
    return result


def _get_key_info(pub_key) -> dict:
    """Extract key type, size, and curve info."""
    if isinstance(pub_key, rsa.RSAPublicKey):
        return {"type": "RSA", "bits": pub_key.key_size, "curve": None}
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        return {"type": "EC", "bits": pub_key.key_size, "curve": pub_key.curve.name}
    elif isinstance(pub_key, dsa.DSAPublicKey):
        return {"type": "DSA", "bits": pub_key.key_size, "curve": None}
    else:
        return {"type": "Unknown", "bits": None, "curve": None}


def _get_key_usage(parsed: x509.Certificate) -> list:
    """Extract key usage extension."""
    # Basic fields safe to read unconditionally
    basic_fields = [
        "digital_signature", "content_commitment", "key_encipherment",
        "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign",
    ]
    # encipher_only / decipher_only raise ValueError unless key_agreement is True
    key_agreement_fields = ["encipher_only", "decipher_only"]

    try:
        ku = parsed.extensions.get_extension_for_class(x509.KeyUsage).value
        result = [f for f in basic_fields if getattr(ku, f, False)]
        if ku.key_agreement:
            result += [f for f in key_agreement_fields if getattr(ku, f, False)]
        return result
    except x509.ExtensionNotFound:
        return []


def _get_ext_key_usage(parsed: x509.Certificate) -> list:
    """Extract extended key usage extension."""
    eku_map = {
        "1.3.6.1.5.5.7.3.1": "TLS Web Server Authentication",
        "1.3.6.1.5.5.7.3.2": "TLS Web Client Authentication",
        "1.3.6.1.5.5.7.3.3": "Code Signing",
        "1.3.6.1.5.5.7.3.4": "Email Protection",
        "1.3.6.1.5.5.7.3.8": "Time Stamping",
        "1.3.6.1.5.5.7.3.9": "OCSP Signing",
    }
    try:
        eku = parsed.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        return [eku_map.get(u.dotted_string, u.dotted_string) for u in eku]
    except x509.ExtensionNotFound:
        return []


def _get_ocsp_urls(parsed: x509.Certificate) -> list:
    """Extract OCSP URLs from AIA extension."""
    try:
        aia = parsed.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess
        ).value
        return [
            desc.access_location.value
            for desc in aia
            if desc.access_method == x509.AuthorityInformationAccessOID.OCSP
        ]
    except x509.ExtensionNotFound:
        return []


def _get_crl_urls(parsed: x509.Certificate) -> list:
    """Extract CRL distribution point URLs."""
    try:
        cdp = parsed.extensions.get_extension_for_class(
            x509.CRLDistributionPoints
        ).value
        urls = []
        for dp in cdp:
            if dp.full_name:
                for name in dp.full_name:
                    if hasattr(name, "value"):
                        urls.append(name.value)
        return urls
    except x509.ExtensionNotFound:
        return []


def _is_ca(parsed: x509.Certificate) -> bool:
    """Check if certificate is a CA certificate."""
    try:
        bc = parsed.extensions.get_extension_for_class(x509.BasicConstraints).value
        return bc.ca
    except x509.ExtensionNotFound:
        return False
