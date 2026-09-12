"""
Substrate abstraction layer for Bittensor C-to-Safe-Rust Subnet.
Provides seamless fallback to a high-fidelity local mock when native
bittensor C-extensions are unavailable on the host.
"""

import sys
import os
import time
import uuid
import asyncio
import logging
from typing import Dict, List, Optional, Any, Callable
from pydantic import BaseModel, Field

# Setup basic logging
logger = logging.getLogger("substrate")
if not logger.handlers:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

# Check if real bittensor can be imported
_REAL_BITTENSOR = False
try:
    import bittensor as bt
    _REAL_BITTENSOR = True
except Exception:
    _REAL_BITTENSOR = False

# Check if mock mode is explicitly requested
_ALLOW_MOCK = ("--mock" in sys.argv) or (os.environ.get("AEGIS_MOCK") == "1") or (os.environ.get("FORCE_MOCK_BITTENSOR") == "1")

if _REAL_BITTENSOR and not _ALLOW_MOCK:
    Synapse = bt.Synapse
    axon = bt.axon
    dendrite = bt.dendrite
    wallet = bt.wallet
    metagraph = bt.metagraph
    bt_logging = bt.logging
    Keypair = getattr(bt, "Keypair", None)
    IS_MOCK = False
    logger.info("[substrate] Using the real bittensor SDK (network mode).")

    def subtensor(network: str = "finney", netuid: int = 1):
        """The real Subtensor is not scoped to a netuid; neurons pass one for the mock's sake."""
        return bt.subtensor(network=network)
elif _ALLOW_MOCK:
    IS_MOCK = True
    logger.info("[substrate] Initializing high-fidelity Mock Bittensor substrate engine (--mock enabled).")

    class TerminalInfo(BaseModel):
        status_code: int = 200
        status_message: str = "Success"
        process_time: float = 0.0

    class Synapse(BaseModel):
        """Standard Bittensor Synapse protocol base class."""
        synapse_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
        timestamp: float = Field(default_factory=time.time)
        dendrite: TerminalInfo = Field(default_factory=TerminalInfo)
        axon: TerminalInfo = Field(default_factory=TerminalInfo)

        class Config:
            arbitrary_types_allowed = True

        def deserialize(self) -> Any:
            return self


        def deserialize(self) -> Any:
            return self

    class Wallet:
        def __init__(self, name: str = "default", hotkey: str = "default"):
            self.name = name
            self.hotkey_str = hotkey
            self.hotkey = self
            self.ss58_address = f"5Mock{name.capitalize()}{hotkey.capitalize()}Address"

        def __repr__(self):
            return f"Wallet(name={self.name}, hotkey={self.hotkey_str}, ss58={self.ss58_address})"

    class AxonInfo:
        def __init__(self, ip: str = "127.0.0.1", port: int = 8091, hotkey: str = "mock_hotkey"):
            self.ip = ip
            self.port = port
            self.hotkey = hotkey
            self.is_serving = True

        def is_serving(self):
            return True

    class Metagraph:
        def __init__(self, netuid: int = 1):
            self.netuid = netuid
            self.hotkeys: List[str] = []
            self.axons: List[AxonInfo] = []
            self.uids: List[int] = []
            self.weights: List[float] = []
            self.n: int = 0
            self.block: int = 1000

        def sync(self, subtensor=None):
            return self

        def register_neuron(self, hotkey: str, ip: str = "127.0.0.1", port: int = 8091) -> int:
            uid = len(self.hotkeys)
            self.hotkeys.append(hotkey)
            self.axons.append(AxonInfo(ip=ip, port=port, hotkey=hotkey))
            self.uids.append(uid)
            self.weights.append(0.0)
            self.n = len(self.hotkeys)
            return uid

    # In-memory mock registry for localnet routing
    _MOCK_METAGRAPH_REGISTRY: Dict[int, Metagraph] = {}
    _MOCK_FORWARD_HANDLERS: Dict[str, Dict[str, Callable]] = {}

    class Subtensor:
        def __init__(self, network: str = "local", netuid: int = 1):
            self.network = network
            self.netuid = netuid
            self.current_block = 1000

        def get_current_block(self) -> int:
            self.current_block += 1
            return self.current_block

        def metagraph(self, netuid: Optional[int] = None) -> Metagraph:
            uid = netuid if netuid is not None else self.netuid
            if uid not in _MOCK_METAGRAPH_REGISTRY:
                _MOCK_METAGRAPH_REGISTRY[uid] = Metagraph(netuid=uid)
            return _MOCK_METAGRAPH_REGISTRY[uid]

        def set_weights(self, netuid: int, wallet: Any, uids: List[int], weights: List[float], version_key: int = 0):
            logger.info(f"[subtensor] Setting weights on netuid {netuid}: uids={uids}, weights={[round(w, 4) for w in weights]}")
            meta = self.metagraph(netuid)
            for uid, w in zip(uids, weights):
                if uid < len(meta.weights):
                    meta.weights[uid] = float(w)
            return True, "Weights set successfully"

    class Axon:
        def __init__(self, wallet: Wallet, port: int = 8091, ip: str = "127.0.0.1", config=None):
            self.wallet = wallet
            self.hotkey = wallet.hotkey_str
            self.port = port
            self.ip = ip
            self.forward_handlers: Dict[str, Callable] = {}
            _MOCK_FORWARD_HANDLERS[self.wallet.ss58_address] = self.forward_handlers
            _MOCK_FORWARD_HANDLERS[self.wallet.hotkey_str] = self.forward_handlers

        def attach(self, forward_fn: Callable, blacklist_fn: Optional[Callable] = None, priority_fn: Optional[Callable] = None):
            import inspect
            synapse_type = None
            try:
                sig = inspect.signature(forward_fn)
                for p in sig.parameters.values():
                    ann = p.annotation
                    if ann != inspect.Parameter.empty:
                        if isinstance(ann, type) and issubclass(ann, Synapse):
                            synapse_type = ann.__name__
                            break
                        elif isinstance(ann, str) and "Synapse" in ann:
                            synapse_type = ann
                            break
            except Exception:
                pass

            if not synapse_type:
                type_hints = getattr(forward_fn, "__annotations__", {})
                for k, v in type_hints.items():
                    if k != "return" and isinstance(v, type) and issubclass(v, Synapse):
                        synapse_type = v.__name__
                        break

            if not synapse_type:
                synapse_type = forward_fn.__name__

            self.forward_handlers[synapse_type] = forward_fn
            self.forward_handlers["forward"] = forward_fn
            return self

        def start(self):
            logger.info(f"[axon] Started mock Axon on {self.ip}:{self.port} for hotkey {self.wallet.ss58_address}")
            return self

        def stop(self):
            logger.info(f"[axon] Stopped mock Axon on {self.ip}:{self.port}")
            return self

    class Dendrite:
        def __init__(self, wallet: Wallet):
            self.wallet = wallet

        async def forward(self, axons: List[Any], synapse: Synapse, timeout: float = 12.0) -> List[Synapse]:
            responses = []
            for ax in axons:
                hotkey = (
                    getattr(ax, "hotkey", None)
                    or getattr(getattr(ax, "wallet", None), "hotkey_str", None)
                    or getattr(getattr(ax, "wallet", None), "ss58_address", None)
                )
                handlers = _MOCK_FORWARD_HANDLERS.get(hotkey, {})
                syn_type = synapse.__class__.__name__
                handler = handlers.get(syn_type) or handlers.get("forward")

                if handler:
                    start_t = time.time()
                    try:
                        syn_copy = synapse.model_copy(deep=True)
                        import inspect
                        if inspect.iscoroutinefunction(handler):
                            result = await asyncio.wait_for(handler(syn_copy), timeout=timeout)
                        else:
                            result = handler(syn_copy)
                        elapsed = time.time() - start_t
                        result.dendrite.process_time = elapsed
                        result.dendrite.status_code = 200
                        result.dendrite.status_message = "Success"
                        responses.append(result)
                    except asyncio.TimeoutError:
                        syn_err = synapse.model_copy(deep=True)
                        syn_err.dendrite.status_code = 408
                        syn_err.dendrite.status_message = "Request Timeout"
                        responses.append(syn_err)
                    except Exception as e:
                        syn_err = synapse.model_copy(deep=True)
                        syn_err.dendrite.status_code = 500
                        syn_err.dendrite.status_message = str(e)
                        responses.append(syn_err)
                else:
                    syn_err = synapse.model_copy(deep=True)
                    syn_err.dendrite.status_code = 404
                    syn_err.dendrite.status_message = f"No handler registered for {syn_type}"
                    responses.append(syn_err)
            return responses

        def query(self, axons: List[Any], synapse: Synapse, timeout: float = 12.0) -> List[Synapse]:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    import concurrent.futures
                    with concurrent.futures.ThreadPoolExecutor() as pool:
                        return pool.submit(asyncio.run, self.forward(axons, synapse, timeout)).result()
                else:
                    return loop.run_until_complete(self.forward(axons, synapse, timeout))
            except RuntimeError:
                return asyncio.run(self.forward(axons, synapse, timeout))

    # Helper factories
    def wallet(name: str = "default", hotkey: str = "default") -> Wallet:
        return Wallet(name=name, hotkey=hotkey)

    def axon(wallet: Wallet, port: int = 8091, ip: str = "127.0.0.1", config=None) -> Axon:
        return Axon(wallet=wallet, port=port, ip=ip, config=config)

    def dendrite(wallet: Wallet) -> Dendrite:
        return Dendrite(wallet=wallet)

    def subtensor(network: str = "local", netuid: int = 1) -> Subtensor:
        return Subtensor(network=network, netuid=netuid)

    def logging():
        return logger
else:
    raise ImportError(
        "Real 'bittensor' package is required for live/testnet operation. "
        "Install with `pip install bittensor` or specify `--mock` (or set `AEGIS_MOCK=1`) "
        "to run the local mock substrate simulation."
    )

