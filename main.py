# main.py
import ipaddress
import json
import sqlite3
import uuid
from decimal import Decimal
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.responses import FileResponse, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

import biometrics
import storage
from auth import hash_password, verify_password, create_access_token, decode_access_token
from wallet import (
    NETWORKS,
    create_account_keypair,
    decrypt_mnemonic,
    decrypt_private_key,
    encrypt_mnemonic,
    encrypt_private_key,
    generate_mnemonic,
    get_balance,
    send_native,
)

FRONTEND_DIR = Path(__file__).parent / "frontend"

app = FastAPI(title="TON 618 Wallet")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
storage.init_db()


class SignupFingerprintOptionsRequest(BaseModel):
    email: EmailStr


class SignupFingerprint(BaseModel):
    signup_id: str
    credential: Dict[str, Any]


class SignupRequest(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    fingerprint: Optional[SignupFingerprint] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserResponse(BaseModel):
    id: str
    email: EmailStr
    has_fingerprint: bool = False


class ChangeEmailRequest(BaseModel):
    new_email: EmailStr
    password: str = Field(min_length=8)


class ChangePasswordRequest(BaseModel):
    current_password: str = Field(min_length=8)
    new_password: str = Field(min_length=8)


class FingerprintLoginOptionsRequest(BaseModel):
    email: EmailStr


class FingerprintLoginRequest(BaseModel):
    email: EmailStr
    credential: Dict[str, Any]


class FingerprintRegisterOptionsRequest(BaseModel):
    wallet_id: Optional[str] = None


class FingerprintCredentialRequest(BaseModel):
    credential: Dict[str, Any]
    wallet_id: Optional[str] = None


class DeleteWalletOptionsRequest(BaseModel):
    password: str = Field(min_length=8)


class DeleteWalletRequest(BaseModel):
    password: str = Field(min_length=8)
    credential: Dict[str, Any]


class CreateWalletRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)


class WalletSummary(BaseModel):
    id: str
    name: str
    account_count: int
    max_accounts: int
    has_seed: bool = False
    has_fingerprint: bool = False
    mnemonic: Optional[str] = None


class RevealSeedRequest(BaseModel):
    password: str = Field(min_length=8)


class SeedPhraseResponse(BaseModel):
    wallet_id: str
    wallet_name: str
    mnemonic: str
    word_count: int


class NetworkOption(BaseModel):
    id: str
    label: str
    symbol: str


class CreateAccountRequest(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    network: str
    password: str = Field(min_length=8)


class AccountResponse(BaseModel):
    id: str
    wallet_id: str
    name: str
    network: str
    network_label: str
    address: str
    created_at: str


class AccountsPayload(BaseModel):
    wallet_id: str
    wallet_name: str
    accounts: List[AccountResponse]
    account_count: int
    max_accounts: int
    can_add_account: bool


class BalanceResponse(BaseModel):
    address: str
    amount: str
    symbol: str
    network: str
    network_label: str
    raw: str


class SendRequest(BaseModel):
    to_address: str = ""
    amount: str = Field(min_length=1)
    password: str = Field(min_length=8)
    to_account_id: Optional[str] = None


class SendResponse(BaseModel):
    tx_hash: str
    from_address: str
    to_address: str
    amount: str
    symbol: str
    network: str
    network_label: str
    explorer_url: str


class PortfolioAccountBalance(BaseModel):
    id: str
    name: str
    network: str
    network_label: str
    address: str
    amount: str
    symbol: str
    raw: str


class PortfolioAssetTotal(BaseModel):
    symbol: str
    amount: str
    account_count: int


class PortfolioResponse(BaseModel):
    wallet_id: str
    wallet_name: str
    totals: List[PortfolioAssetTotal]
    accounts: List[PortfolioAccountBalance]


def _account_response(account: dict) -> AccountResponse:
    network = account["network"]
    label = NETWORKS.get(network, {}).get("label", network)
    return AccountResponse(
        id=account["id"],
        wallet_id=account["wallet_id"],
        name=account["name"],
        network=network,
        network_label=label,
        address=account["address"],
        created_at=account["created_at"],
    )


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/networks", response_model=List[NetworkOption])
def list_networks():
    return [
        NetworkOption(id=network_id, label=meta["label"], symbol=meta["symbol"])
        for network_id, meta in NETWORKS.items()
    ]


@app.post("/auth/signup/fingerprint/options")
def signup_fingerprint_options(payload: SignupFingerprintOptionsRequest, request: Request):
    if storage.get_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    rp_id, _origin = _webauthn_context(request)
    signup_id = str(uuid.uuid4())
    options = biometrics.registration_options(
        user_id=signup_id,
        email=payload.email,
        rp_id=rp_id,
        existing_credential_ids=[],
    )
    return {"signup_id": signup_id, "options": json.loads(options)}


@app.post("/auth/signup", response_model=TokenResponse, status_code=201)
def signup(payload: SignupRequest, request: Request):
    if storage.get_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail="Email already registered")

    user_id = str(uuid.uuid4())
    registered = None
    if payload.fingerprint is not None:
        rp_id, origin = _webauthn_context(request)
        try:
            registered = biometrics.verify_registration(
                user_id=payload.fingerprint.signup_id,
                credential=payload.fingerprint.credential,
                rp_id=rp_id,
                origin=origin,
            )
        except Exception as exc:
            raise HTTPException(
                status_code=400, detail=f"Fingerprint registration failed: {exc}"
            ) from exc
        user_id = payload.fingerprint.signup_id

    try:
        storage.create_user(
            user_id, payload.email, hash_password(payload.password), credential=registered
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=400, detail="Email or fingerprint already registered"
        ) from exc
    return TokenResponse(access_token=create_access_token(user_id))


@app.post("/auth/login", response_model=TokenResponse)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = storage.get_user_by_email(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    return TokenResponse(access_token=create_access_token(user["id"]))


@app.post("/auth/login/fingerprint/options")
def fingerprint_login_options(payload: FingerprintLoginOptionsRequest, request: Request):
    rp_id, _origin = _webauthn_context(request)
    user = storage.get_user_by_email(payload.email)
    credentials = storage.list_webauthn_credentials(user["id"]) if user else []
    if not credentials:
        # Same response shape as a real challenge so emails can't be probed.
        options = biometrics.decoy_authentication_options(rp_id)
    else:
        options = biometrics.authentication_options(
            user_id=user["id"],
            purpose="login",
            rp_id=rp_id,
            credential_ids=[c["id"] for c in credentials],
        )
    return Response(content=options, media_type="application/json")


@app.post("/auth/login/fingerprint", response_model=TokenResponse)
def fingerprint_login(payload: FingerprintLoginRequest, request: Request):
    rp_id, origin = _webauthn_context(request)
    failed = HTTPException(status_code=401, detail="Fingerprint not recognised for this email")

    user = storage.get_user_by_email(payload.email)
    if user is None:
        raise failed
    credentials = {c["id"]: c for c in storage.list_webauthn_credentials(user["id"])}
    stored = credentials.get(str(payload.credential.get("id", "")))
    if stored is None:
        raise failed

    try:
        new_sign_count = biometrics.verify_authentication(
            user_id=user["id"],
            purpose="login",
            credential=payload.credential,
            stored_credential=stored,
            rp_id=rp_id,
            origin=origin,
        )
    except Exception as exc:
        raise failed from exc

    storage.update_webauthn_sign_count(stored["id"], new_sign_count)
    return TokenResponse(access_token=create_access_token(user["id"]))


def get_current_user(token: str = Depends(oauth2_scheme)):
    user_id = decode_access_token(token)
    if user_id is None:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    user = storage.get_user_by_id(user_id)
    if user is None:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
    return user


def _user_response(user: dict) -> UserResponse:
    return UserResponse(
        id=user["id"],
        email=user["email"],
        has_fingerprint=bool(storage.list_webauthn_credentials(user["id"])),
    )


def _require_password(user: dict, password: str) -> None:
    if not verify_password(password, user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect password")


def _webauthn_context(request: Request) -> Tuple[str, str]:
    host = request.url.hostname or ""
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host, f"{request.url.scheme}://{request.url.netloc}"
    raise HTTPException(
        status_code=400,
        detail="Fingerprint needs the app opened via localhost, not an IP address",
    )


@app.get("/me", response_model=UserResponse)
def me(current_user: dict = Depends(get_current_user)):
    return _user_response(current_user)


@app.post("/me/email", response_model=UserResponse)
def change_email(payload: ChangeEmailRequest, current_user: dict = Depends(get_current_user)):
    _require_password(current_user, payload.password)

    new_email = payload.new_email.strip()
    if new_email.lower() == current_user["email"].lower():
        raise HTTPException(status_code=400, detail="That is already your email")
    if storage.get_user_by_email(new_email):
        raise HTTPException(status_code=400, detail="Email already registered")

    try:
        storage.update_user_email(current_user["id"], new_email)
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=400, detail="Email already registered") from exc

    return _user_response({**current_user, "email": new_email})


@app.post("/me/password")
def change_password(
    payload: ChangePasswordRequest,
    current_user: dict = Depends(get_current_user),
):
    _require_password(current_user, payload.current_password)
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail="New password must be different")

    storage.update_user_password(current_user["id"], hash_password(payload.new_password))
    return {"status": "ok"}


def _owned_wallet(wallet_id: str, user: dict) -> dict:
    wallet = storage.get_wallet_for_user(wallet_id, user["id"])
    if wallet is None:
        raise HTTPException(status_code=404, detail="Wallet not found")
    return wallet


@app.post("/webauthn/register/options")
def fingerprint_register_options(
    request: Request,
    payload: Optional[FingerprintRegisterOptionsRequest] = None,
    current_user: dict = Depends(get_current_user),
):
    rp_id, _origin = _webauthn_context(request)
    wallet_id = payload.wallet_id if payload else None
    if wallet_id:
        wallet = _owned_wallet(wallet_id, current_user)
        existing = [c["id"] for c in storage.list_wallet_credentials(wallet_id)]
        options = biometrics.registration_options(
            user_id=current_user["id"],
            email=current_user["email"],
            rp_id=rp_id,
            existing_credential_ids=existing,
            purpose=f"register:{wallet_id}",
            user_handle=wallet_id,
            display_name=f"{current_user['email']} · {wallet['name']}",
        )
    else:
        existing = [c["id"] for c in storage.list_webauthn_credentials(current_user["id"])]
        options = biometrics.registration_options(
            user_id=current_user["id"],
            email=current_user["email"],
            rp_id=rp_id,
            existing_credential_ids=existing,
        )
    return Response(content=options, media_type="application/json")


@app.post("/webauthn/register/verify", response_model=UserResponse)
def fingerprint_register_verify(
    payload: FingerprintCredentialRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    rp_id, origin = _webauthn_context(request)
    if payload.wallet_id:
        _owned_wallet(payload.wallet_id, current_user)
    try:
        registered = biometrics.verify_registration(
            user_id=current_user["id"],
            credential=payload.credential,
            rp_id=rp_id,
            origin=origin,
            purpose=f"register:{payload.wallet_id}" if payload.wallet_id else "register",
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Fingerprint registration failed: {exc}") from exc

    try:
        storage.add_webauthn_credential(
            credential_id=registered["id"],
            user_id=current_user["id"],
            public_key=registered["public_key"],
            sign_count=registered["sign_count"],
            wallet_id=payload.wallet_id,
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=400, detail="Fingerprint already registered") from exc

    return _user_response(current_user)


@app.get("/wallets", response_model=List[WalletSummary])
def list_wallets(current_user: dict = Depends(get_current_user)):
    wallets = storage.list_wallets_by_user(current_user["id"])
    fingerprinted = {
        c["wallet_id"] for c in storage.list_webauthn_credentials(current_user["id"]) if c["wallet_id"]
    }
    return [
        WalletSummary(
            id=w["id"],
            name=w["name"],
            account_count=w["account_count"],
            max_accounts=storage.MAX_ACCOUNTS_PER_WALLET,
            has_seed=bool(w.get("encrypted_mnemonic")),
            has_fingerprint=w["id"] in fingerprinted,
        )
        for w in wallets
    ]


@app.post("/wallets", response_model=WalletSummary, status_code=201)
def create_wallet_named(
    payload: CreateWalletRequest,
    current_user: dict = Depends(get_current_user),
):
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Wallet name is required")

    mnemonic = generate_mnemonic()
    try:
        wallet = storage.create_named_wallet(
            wallet_id=str(uuid.uuid4()),
            user_id=current_user["id"],
            name=name,
            encrypted_mnemonic=encrypt_mnemonic(mnemonic),
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=400, detail="Wallet name already exists") from exc

    storage.bind_unassigned_credentials(current_user["id"], wallet["id"])
    return WalletSummary(
        id=wallet["id"],
        name=wallet["name"],
        account_count=0,
        max_accounts=storage.MAX_ACCOUNTS_PER_WALLET,
        has_seed=True,
        has_fingerprint=bool(storage.list_wallet_credentials(wallet["id"])),
        mnemonic=mnemonic,
    )


@app.post("/wallets/{wallet_id}/delete/options")
def delete_wallet_options(
    wallet_id: str,
    payload: DeleteWalletOptionsRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    _owned_wallet(wallet_id, current_user)
    _require_password(current_user, payload.password)

    rp_id, _origin = _webauthn_context(request)
    credentials = storage.list_wallet_credentials(wallet_id)
    if not credentials:
        raise HTTPException(
            status_code=400,
            detail="Set up a fingerprint for this wallet before deleting it",
        )

    options = biometrics.authentication_options(
        user_id=current_user["id"],
        purpose=f"delete:{wallet_id}",
        rp_id=rp_id,
        credential_ids=[c["id"] for c in credentials],
    )
    return Response(content=options, media_type="application/json")


@app.post("/wallets/{wallet_id}/delete")
def delete_wallet(
    wallet_id: str,
    payload: DeleteWalletRequest,
    request: Request,
    current_user: dict = Depends(get_current_user),
):
    _owned_wallet(wallet_id, current_user)
    _require_password(current_user, payload.password)

    rp_id, origin = _webauthn_context(request)
    credentials = {c["id"]: c for c in storage.list_wallet_credentials(wallet_id)}
    stored = credentials.get(str(payload.credential.get("id", "")))
    if stored is None:
        raise HTTPException(status_code=401, detail="Fingerprint not recognised for this wallet")

    try:
        new_sign_count = biometrics.verify_authentication(
            user_id=current_user["id"],
            purpose=f"delete:{wallet_id}",
            credential=payload.credential,
            stored_credential=stored,
            rp_id=rp_id,
            origin=origin,
        )
    except Exception as exc:
        raise HTTPException(status_code=401, detail=f"Fingerprint verification failed: {exc}") from exc

    storage.update_webauthn_sign_count(stored["id"], new_sign_count)
    revoked = storage.delete_wallet(wallet_id)
    return {"deleted": True, "wallet_id": wallet_id, "revoked_credential_ids": revoked}


@app.post("/wallets/{wallet_id}/seed", response_model=SeedPhraseResponse)
def reveal_wallet_seed(
    wallet_id: str,
    payload: RevealSeedRequest,
    current_user: dict = Depends(get_current_user),
):
    wallet = storage.get_wallet_for_user(wallet_id, current_user["id"])
    if wallet is None:
        raise HTTPException(status_code=404, detail="Wallet not found")

    if not verify_password(payload.password, current_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect password")

    encrypted = wallet.get("encrypted_mnemonic")
    if not encrypted:
        # Legacy wallets created before seed phrases — generate one now.
        mnemonic = generate_mnemonic()
        storage.set_wallet_mnemonic(wallet_id, encrypt_mnemonic(mnemonic))
    else:
        try:
            mnemonic = decrypt_mnemonic(encrypted)
        except Exception as exc:
            raise HTTPException(status_code=500, detail="Could not decrypt seed phrase") from exc

    words = mnemonic.strip().split()
    return SeedPhraseResponse(
        wallet_id=wallet["id"],
        wallet_name=wallet["name"],
        mnemonic=mnemonic,
        word_count=len(words),
    )


@app.get("/wallets/{wallet_id}/accounts", response_model=AccountsPayload)
def get_wallet_accounts(wallet_id: str, current_user: dict = Depends(get_current_user)):
    wallet = storage.get_wallet_for_user(wallet_id, current_user["id"])
    if wallet is None:
        raise HTTPException(status_code=404, detail="Wallet not found")

    accounts = storage.list_accounts(wallet_id)
    count = len(accounts)
    max_accounts = storage.MAX_ACCOUNTS_PER_WALLET
    return AccountsPayload(
        wallet_id=wallet["id"],
        wallet_name=wallet["name"],
        accounts=[_account_response(a) for a in accounts],
        account_count=count,
        max_accounts=max_accounts,
        can_add_account=count < max_accounts,
    )


@app.post(
    "/wallets/{wallet_id}/accounts",
    response_model=AccountResponse,
    status_code=201,
)
def add_account(
    wallet_id: str,
    payload: CreateAccountRequest,
    current_user: dict = Depends(get_current_user),
):
    wallet = storage.get_wallet_for_user(wallet_id, current_user["id"])
    if wallet is None:
        raise HTTPException(status_code=404, detail="Wallet not found")

    if not verify_password(payload.password, current_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect password")

    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Account name is required")

    if payload.network not in NETWORKS:
        raise HTTPException(status_code=400, detail="Unsupported network")

    count = storage.count_accounts(wallet_id)
    if count >= storage.MAX_ACCOUNTS_PER_WALLET:
        raise HTTPException(
            status_code=400,
            detail=f"Maximum of {storage.MAX_ACCOUNTS_PER_WALLET} accounts reached",
        )

    generated = create_account_keypair(
        network=payload.network,
        mnemonic=(
            decrypt_mnemonic(wallet["encrypted_mnemonic"])
            if wallet.get("encrypted_mnemonic")
            else None
        ),
        index=count,
    )
    try:
        account = storage.create_account_row(
            account_id=str(uuid.uuid4()),
            wallet_id=wallet_id,
            name=name,
            network=payload.network,
            address=generated["address"],
            encrypted_private_key=encrypt_private_key(generated["private_key"]),
        )
    except sqlite3.IntegrityError as exc:
        raise HTTPException(
            status_code=400,
            detail="Account name already used in this wallet",
        ) from exc

    return _account_response(account)


@app.get("/accounts/{account_id}/balance", response_model=BalanceResponse)
def account_balance(account_id: str, current_user: dict = Depends(get_current_user)):
    account = storage.get_account_by_id(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")

    wallet = storage.get_wallet_for_user(account["wallet_id"], current_user["id"])
    if wallet is None:
        raise HTTPException(status_code=404, detail="Account not found")

    try:
        balance = get_balance(account["network"], account["address"])
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"RPC error: {exc}") from exc

    return BalanceResponse(
        address=account["address"],
        amount=balance["amount"],
        symbol=balance["symbol"],
        network=balance["network"],
        network_label=balance["network_label"],
        raw=balance["raw"],
    )


@app.get("/wallets/{wallet_id}/portfolio", response_model=PortfolioResponse)
def wallet_portfolio(wallet_id: str, current_user: dict = Depends(get_current_user)):
    wallet = storage.get_wallet_for_user(wallet_id, current_user["id"])
    if wallet is None:
        raise HTTPException(status_code=404, detail="Wallet not found")

    accounts = storage.list_accounts(wallet_id)
    account_balances: List[PortfolioAccountBalance] = []
    totals_raw: dict = {}
    totals_count: dict = {}

    for account in accounts:
        label = NETWORKS.get(account["network"], {}).get("label", account["network"])
        try:
            balance = get_balance(account["network"], account["address"])
            amount = balance["amount"]
            symbol = balance["symbol"]
            raw = balance["raw"]
            totals_raw[symbol] = totals_raw.get(symbol, Decimal("0")) + Decimal(amount)
            totals_count[symbol] = totals_count.get(symbol, 0) + 1
        except Exception:
            amount = "—"
            symbol = NETWORKS.get(account["network"], {}).get("symbol", "?")
            raw = "0"

        account_balances.append(
            PortfolioAccountBalance(
                id=account["id"],
                name=account["name"],
                network=account["network"],
                network_label=label,
                address=account["address"],
                amount=amount,
                symbol=symbol,
                raw=raw,
            )
        )

    totals = [
        PortfolioAssetTotal(
            symbol=symbol,
            amount=f"{totals_raw[symbol]:.8f}".rstrip("0").rstrip(".") or "0",
            account_count=totals_count[symbol],
        )
        for symbol in sorted(totals_raw.keys())
    ]

    return PortfolioResponse(
        wallet_id=wallet["id"],
        wallet_name=wallet["name"],
        totals=totals,
        accounts=account_balances,
    )


@app.post("/accounts/{account_id}/send", response_model=SendResponse)
def send_from_account(
    account_id: str,
    payload: SendRequest,
    current_user: dict = Depends(get_current_user),
):
    account = storage.get_account_by_id(account_id)
    if account is None:
        raise HTTPException(status_code=404, detail="Account not found")

    wallet = storage.get_wallet_for_user(account["wallet_id"], current_user["id"])
    if wallet is None:
        raise HTTPException(status_code=404, detail="Account not found")

    if not verify_password(payload.password, current_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Incorrect password")

    to_address = payload.to_address.strip()
    if payload.to_account_id:
        dest = storage.get_account_by_id(payload.to_account_id)
        if dest is None:
            raise HTTPException(status_code=404, detail="Destination account not found")
        dest_wallet = storage.get_wallet_for_user(dest["wallet_id"], current_user["id"])
        if dest_wallet is None:
            raise HTTPException(status_code=404, detail="Destination account not found")
        if dest["network"] != account["network"]:
            raise HTTPException(
                status_code=400,
                detail="Destination account must be on the same network",
            )
        if dest["id"] == account["id"]:
            raise HTTPException(status_code=400, detail="Cannot send to the same account")
        to_address = dest["address"]
    elif not to_address:
        raise HTTPException(status_code=400, detail="Destination address is required")

    try:
        private_key = decrypt_private_key(account["encrypted_private_key"])
        result = send_native(
            network=account["network"],
            private_key=private_key,
            to_address=to_address,
            amount=payload.amount,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Send failed: {exc}") from exc

    return SendResponse(**result)


@app.get("/")
def frontend_index():
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
