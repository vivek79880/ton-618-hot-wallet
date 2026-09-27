# biometrics.py
from __future__ import annotations

import secrets
import time
from typing import Any, Dict, List, Optional, Tuple

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

RP_NAME = "TON 618 Wallet"
CHALLENGE_TTL_SECONDS = 300

# Single-process dev server, so pending challenges can live in memory.
_challenges: Dict[Tuple[str, str], Tuple[bytes, float]] = {}


def _store_challenge(user_id: str, purpose: str, challenge: bytes) -> None:
    _challenges[(user_id, purpose)] = (challenge, time.time() + CHALLENGE_TTL_SECONDS)


def _pop_challenge(user_id: str, purpose: str) -> bytes:
    entry = _challenges.pop((user_id, purpose), None)
    if entry is None or entry[1] < time.time():
        raise ValueError("Fingerprint request expired. Please try again.")
    return entry[0]


def _descriptors(credential_ids: List[str]) -> List[PublicKeyCredentialDescriptor]:
    return [PublicKeyCredentialDescriptor(id=base64url_to_bytes(cid)) for cid in credential_ids]


def registration_options(
    user_id: str,
    email: str,
    rp_id: str,
    existing_credential_ids: List[str],
    purpose: str = "register",
    user_handle: Optional[str] = None,
    display_name: Optional[str] = None,
) -> str:
    # Each wallet's passkey gets its own user handle; platform authenticators
    # replace an existing passkey that shares the same RP ID and user handle.
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name=RP_NAME,
        user_id=(user_handle or user_id).encode(),
        user_name=email,
        user_display_name=display_name or email,
        authenticator_selection=AuthenticatorSelectionCriteria(
            authenticator_attachment=AuthenticatorAttachment.PLATFORM,
            user_verification=UserVerificationRequirement.REQUIRED,
            resident_key=ResidentKeyRequirement.DISCOURAGED,
        ),
        exclude_credentials=_descriptors(existing_credential_ids),
    )
    _store_challenge(user_id, purpose, options.challenge)
    return options_to_json(options)


def verify_registration(
    user_id: str,
    credential: Dict[str, Any],
    rp_id: str,
    origin: str,
    purpose: str = "register",
) -> dict:
    verified = verify_registration_response(
        credential=credential,
        expected_challenge=_pop_challenge(user_id, purpose),
        expected_rp_id=rp_id,
        expected_origin=origin,
        require_user_verification=True,
    )
    return {
        "id": bytes_to_base64url(verified.credential_id),
        "public_key": bytes_to_base64url(verified.credential_public_key),
        "sign_count": verified.sign_count,
    }


def authentication_options(
    user_id: str,
    purpose: str,
    rp_id: str,
    credential_ids: List[str],
) -> str:
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=_descriptors(credential_ids),
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    _store_challenge(user_id, purpose, options.challenge)
    return options_to_json(options)


def decoy_authentication_options(rp_id: str) -> str:
    """Options shaped like a real login challenge, for emails with no passkeys."""
    options = generate_authentication_options(
        rp_id=rp_id,
        allow_credentials=_descriptors([bytes_to_base64url(secrets.token_bytes(32))]),
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    return options_to_json(options)


def verify_authentication(
    user_id: str,
    purpose: str,
    credential: Dict[str, Any],
    stored_credential: dict,
    rp_id: str,
    origin: str,
) -> int:
    verified = verify_authentication_response(
        credential=credential,
        expected_challenge=_pop_challenge(user_id, purpose),
        expected_rp_id=rp_id,
        expected_origin=origin,
        credential_public_key=base64url_to_bytes(stored_credential["public_key"]),
        credential_current_sign_count=int(stored_credential["sign_count"]),
        require_user_verification=True,
    )
    return verified.new_sign_count
