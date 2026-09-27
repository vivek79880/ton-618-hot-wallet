# wallet.py
from __future__ import annotations

import base64
import hashlib
from decimal import Decimal, InvalidOperation
from typing import Dict

import httpx
from bit import PrivateKeyTestnet
from cryptography.fernet import Fernet
from eth_account import Account
from solders.hash import Hash
from solders.keypair import Keypair
from solders.message import Message
from solders.pubkey import Pubkey
from solders.system_program import TransferParams, transfer
from solders.transaction import Transaction

from auth import SECRET_KEY

# Required once for BIP39 / HD wallet helpers on eth_account.
Account.enable_unaudited_hdwallet_features()

NETWORKS: Dict[str, Dict[str, str]] = {
    "ethereum_sepolia": {
        "label": "Ethereum Sepolia",
        "symbol": "ETH",
        "rpc": "https://ethereum-sepolia-rpc.publicnode.com",
        "chain_id": 11155111,
        "explorer_tx": "https://sepolia.etherscan.io/tx/",
    },
    "bitcoin_testnet": {
        "label": "Bitcoin Testnet",
        "symbol": "tBTC",
        "rpc": "https://blockstream.info/testnet/api",
        "explorer_tx": "https://mempool.space/testnet/tx/",
    },
    "solana_devnet": {
        "label": "Solana Devnet",
        "symbol": "SOL",
        "rpc": "https://api.devnet.solana.com",
        "explorer_tx": "https://explorer.solana.com/tx/",
    },
}


def _rpc_eth(network: str, method: str, params: list):
    meta = NETWORKS[network]
    response = httpx.post(
        meta["rpc"],
        json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
        timeout=30.0,
    )
    response.raise_for_status()
    data = response.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    return data["result"]


def _parse_amount(amount: str) -> Decimal:
    try:
        value = Decimal(str(amount).strip())
    except (InvalidOperation, ValueError) as exc:
        raise ValueError("Invalid amount") from exc
    if value <= 0:
        raise ValueError("Amount must be greater than zero")
    return value


def _fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(SECRET_KEY.encode()).digest())
    return Fernet(key)


def encrypt_private_key(private_key: str) -> str:
    return _fernet().encrypt(private_key.encode()).decode()


def decrypt_private_key(encrypted: str) -> str:
    return _fernet().decrypt(encrypted.encode()).decode()


def encrypt_mnemonic(mnemonic: str) -> str:
    return encrypt_private_key(mnemonic)


def decrypt_mnemonic(encrypted: str) -> str:
    return decrypt_private_key(encrypted)


def generate_mnemonic() -> str:
    """Create a new 12-word BIP39 seed phrase."""
    _account, mnemonic = Account.create_with_mnemonic()
    return mnemonic


def _deterministic_seed(mnemonic: str, network: str, index: int) -> bytes:
    material = f"foxwallet|{network}|{index}|{mnemonic}".encode()
    return hashlib.sha256(material).digest()


def derive_account_from_mnemonic(network: str, mnemonic: str, index: int) -> dict:
    """Derive a network account from the wallet seed phrase."""
    if network not in NETWORKS:
        raise ValueError(f"Unsupported network: {network}")
    if index < 0:
        raise ValueError("Invalid derivation index")

    if network == "ethereum_sepolia":
        path = f"m/44'/60'/0'/0/{index}"
        account = Account.from_mnemonic(mnemonic, account_path=path)
        return {
            "address": account.address,
            "private_key": account.key.hex(),
            "network": network,
            "derivation_index": index,
        }

    if network == "bitcoin_testnet":
        seed = _deterministic_seed(mnemonic, network, index)
        key = PrivateKeyTestnet.from_bytes(seed)
        return {
            "address": key.address,
            "private_key": key.to_wif(),
            "network": network,
            "derivation_index": index,
        }

    # solana_devnet — 32-byte seed for ed25519 keypair
    seed = _deterministic_seed(mnemonic, network, index)
    keypair = Keypair.from_seed(seed)
    return {
        "address": str(keypair.pubkey()),
        "private_key": bytes(keypair).hex(),
        "network": network,
        "derivation_index": index,
    }


def create_account_keypair(network: str, mnemonic: str | None = None, index: int = 0) -> dict:
    """Generate a keypair — derived from seed when available, else random."""
    if network not in NETWORKS:
        raise ValueError(f"Unsupported network: {network}")

    if mnemonic:
        return derive_account_from_mnemonic(network, mnemonic, index)

    if network == "ethereum_sepolia":
        account = Account.create()
        return {
            "address": account.address,
            "private_key": account.key.hex(),
            "network": network,
            "derivation_index": None,
        }

    if network == "bitcoin_testnet":
        key = PrivateKeyTestnet()
        return {
            "address": key.address,
            "private_key": key.to_wif(),
            "network": network,
            "derivation_index": None,
        }

    keypair = Keypair()
    return {
        "address": str(keypair.pubkey()),
        "private_key": bytes(keypair).hex(),
        "network": network,
        "derivation_index": None,
    }


def get_balance(network: str, address: str) -> dict:
    """Return normalized balance for the account network."""
    meta = NETWORKS[network]
    symbol = meta["symbol"]

    if network == "ethereum_sepolia":
        wei = int(_rpc_eth(network, "eth_getBalance", [address, "latest"]), 16)
        amount = wei / 10**18
        return {
            "amount": f"{amount:.6f}",
            "symbol": symbol,
            "network": network,
            "network_label": meta["label"],
            "raw": str(wei),
        }

    if network == "bitcoin_testnet":
        response = httpx.get(f"{meta['rpc']}/address/{address}", timeout=15.0)
        response.raise_for_status()
        data = response.json()
        funded = data.get("chain_stats", {}).get("funded_txo_sum", 0)
        spent = data.get("chain_stats", {}).get("spent_txo_sum", 0)
        sats = int(funded) - int(spent)
        amount = sats / 10**8
        return {
            "amount": f"{amount:.8f}",
            "symbol": symbol,
            "network": network,
            "network_label": meta["label"],
            "raw": str(sats),
        }

    # solana_devnet — lamports
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address],
    }
    response = httpx.post(meta["rpc"], json=payload, timeout=15.0)
    response.raise_for_status()
    data = response.json()
    if "error" in data:
        raise RuntimeError(data["error"])
    lamports = int(data["result"]["value"])
    amount = lamports / 10**9
    return {
        "amount": f"{amount:.6f}",
        "symbol": symbol,
        "network": network,
        "network_label": meta["label"],
        "raw": str(lamports),
    }


def _send_ethereum(private_key: str, to_address: str, amount: Decimal) -> dict:
    network = "ethereum_sepolia"
    meta = NETWORKS[network]
    account = Account.from_key(private_key)
    from_address = account.address

    if not to_address.startswith("0x") or len(to_address) != 42:
        raise ValueError("Invalid Ethereum address")

    wei = int(amount * Decimal(10**18))
    balance_wei = int(_rpc_eth(network, "eth_getBalance", [from_address, "latest"]), 16)
    nonce = int(_rpc_eth(network, "eth_getTransactionCount", [from_address, "pending"]), 16)
    gas_price = int(_rpc_eth(network, "eth_gasPrice", []), 16)
    gas_limit = 21000
    fee = gas_price * gas_limit
    if balance_wei < wei + fee:
        raise ValueError("Insufficient balance for amount + gas")

    signed = Account.sign_transaction(
        {
            "nonce": nonce,
            "gasPrice": gas_price,
            "gas": gas_limit,
            "to": to_address,
            "value": wei,
            "data": b"",
            "chainId": int(meta["chain_id"]),
        },
        private_key,
    )
    raw = signed.raw_transaction.hex()
    if not raw.startswith("0x"):
        raw = "0x" + raw
    tx_hash = _rpc_eth(network, "eth_sendRawTransaction", [raw])
    return {
        "tx_hash": tx_hash,
        "from_address": from_address,
        "to_address": to_address,
        "amount": f"{amount:.6f}",
        "symbol": meta["symbol"],
        "network": network,
        "network_label": meta["label"],
        "explorer_url": f"{meta['explorer_tx']}{tx_hash}",
    }


def _send_bitcoin(private_key_wif: str, to_address: str, amount: Decimal) -> dict:
    network = "bitcoin_testnet"
    meta = NETWORKS[network]
    key = PrivateKeyTestnet(private_key_wif)
    sats = int(amount * Decimal(10**8))
    if sats < 1:
        raise ValueError("Amount too small")
    if key.get_balance("satoshi") < sats:
        raise ValueError("Insufficient balance")

    tx_hash = key.send([(to_address, sats, "satoshi")])
    return {
        "tx_hash": tx_hash,
        "from_address": key.address,
        "to_address": to_address,
        "amount": f"{amount:.8f}",
        "symbol": meta["symbol"],
        "network": network,
        "network_label": meta["label"],
        "explorer_url": f"{meta['explorer_tx']}{tx_hash}",
    }


def _send_solana(private_key_hex: str, to_address: str, amount: Decimal) -> dict:
    network = "solana_devnet"
    meta = NETWORKS[network]
    keypair = Keypair.from_bytes(bytes.fromhex(private_key_hex))
    from_pubkey = keypair.pubkey()
    try:
        to_pubkey = Pubkey.from_string(to_address)
    except Exception as exc:
        raise ValueError("Invalid Solana address") from exc

    lamports = int(amount * Decimal(10**9))
    if lamports < 1:
        raise ValueError("Amount too small")

    balance_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [str(from_pubkey)],
    }
    balance_resp = httpx.post(meta["rpc"], json=balance_payload, timeout=30.0)
    balance_resp.raise_for_status()
    balance_data = balance_resp.json()
    if "error" in balance_data:
        raise RuntimeError(balance_data["error"])
    if int(balance_data["result"]["value"]) < lamports:
        raise ValueError("Insufficient balance")

    bh_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getLatestBlockhash",
        "params": [{"commitment": "finalized"}],
    }
    bh_resp = httpx.post(meta["rpc"], json=bh_payload, timeout=30.0)
    bh_resp.raise_for_status()
    bh_data = bh_resp.json()
    if "error" in bh_data:
        raise RuntimeError(bh_data["error"])
    blockhash = Hash.from_string(bh_data["result"]["value"]["blockhash"])

    ix = transfer(
        TransferParams(
            from_pubkey=from_pubkey,
            to_pubkey=to_pubkey,
            lamports=lamports,
        )
    )
    message = Message.new_with_blockhash([ix], from_pubkey, blockhash)
    tx = Transaction.new_unsigned(message)
    tx.sign([keypair], blockhash)

    send_payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "sendTransaction",
        "params": [
            base64.b64encode(bytes(tx)).decode(),
            {"encoding": "base64", "preflightCommitment": "confirmed"},
        ],
    }
    send_resp = httpx.post(meta["rpc"], json=send_payload, timeout=30.0)
    send_resp.raise_for_status()
    send_data = send_resp.json()
    if "error" in send_data:
        raise RuntimeError(send_data["error"])
    tx_hash = send_data["result"]
    return {
        "tx_hash": tx_hash,
        "from_address": str(from_pubkey),
        "to_address": to_address,
        "amount": f"{amount:.6f}",
        "symbol": meta["symbol"],
        "network": network,
        "network_label": meta["label"],
        "explorer_url": f"{meta['explorer_tx']}{tx_hash}?cluster=devnet",
    }


def send_native(network: str, private_key: str, to_address: str, amount: str) -> dict:
    """Send native tokens on the account network."""
    if network not in NETWORKS:
        raise ValueError(f"Unsupported network: {network}")

    parsed = _parse_amount(amount)
    to_address = to_address.strip()
    if not to_address:
        raise ValueError("Destination address is required")

    if network == "ethereum_sepolia":
        return _send_ethereum(private_key, to_address, parsed)
    if network == "bitcoin_testnet":
        return _send_bitcoin(private_key, to_address, parsed)
    return _send_solana(private_key, to_address, parsed)
