// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    Nimbrex — "basalt tide / lantern compass"
    ----------------------------------------
    AI-investment-vault-style platform:
    - ERC20 share token (vault shares) with EIP-712 permit
    - Single-asset vault with strategy allocation and guarded rebalancing
    - Mainnet-safe controls: 2-step ownership, reentrancy guards, pausing, rate-limited losses
    - No placeholders: includes a no-arg deployer wrapper with randomized role addresses
*/

/// @notice Minimal ERC20 interface for the underlying asset.
interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function allowance(address, address) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

/// @notice Optional metadata interface (not required for correctness).
interface IERC20Metadata is IERC20 {
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
}

/// @notice Strategy adapter interface used by the vault.
interface INimbrexStrategy {
    /// @dev Called by the vault to invest assets. Strategy should pull funds already held by vault via transfer.
    function onInvest(uint256 assets) external returns (uint256 invested);

    /// @dev Called by the vault to divest assets. Strategy should return funds to the vault.
    function onDivest(uint256 assets) external returns (uint256 returnedAssets);

    /// @dev Total assets currently managed by the strategy and attributable to the vault.
    function totalManagedAssets() external view returns (uint256);

    /// @dev Optional hook to realize PnL and move funds back to the vault.
    function report() external returns (int256 pnl, uint256 totalAfter);
}

library NimbrexMath {
    error NRX_MATH_OVERFLOW();

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }

    function mulDivDown(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        unchecked {
            if (d == 0) revert NRX_MATH_OVERFLOW();
            // 512-bit multiply then divide (assembly); mainstream pattern.
            uint256 prod0;
            uint256 prod1;
            assembly {
                let mm := mulmod(x, y, not(0))
                prod0 := mul(x, y)
                prod1 := sub(sub(mm, prod0), lt(mm, prod0))
            }
            if (prod1 == 0) return prod0 / d;
            if (prod1 >= d) revert NRX_MATH_OVERFLOW();
            uint256 remainder;
            assembly {
                remainder := mulmod(x, y, d)
                prod1 := sub(prod1, gt(remainder, prod0))
                prod0 := sub(prod0, remainder)
            }
            uint256 twos = d & (~d + 1);
            assembly {
                d := div(d, twos)
                prod0 := div(prod0, twos)
                twos := add(div(sub(0, twos), twos), 1)
            }
            prod0 |= prod1 * twos;
            uint256 inv = (3 * d) ^ 2;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            z = prod0 * inv;
        }
    }

    function mulDivUp(uint256 x, uint256 y, uint256 d) internal pure returns (uint256) {
        uint256 z = mulDivDown(x, y, d);
        if (z == 0) {
            if (x == 0 || y == 0) return 0;
        }
        unchecked {
            if (mulmod(x, y, d) != 0) z += 1;
        }
        return z;
    }
}

library NimbrexSafeERC20 {
    error NRX_ERC20_CALL_FAIL();
    error NRX_ERC20_FALSE_RETURN();

    function _callOptionalReturn(IERC20 token, bytes memory data) private returns (bytes memory ret) {
        (bool ok, bytes memory out) = address(token).call(data);
        if (!ok) revert NRX_ERC20_CALL_FAIL();
        if (out.length == 0) return out;
        // Tokens that return a boolean should return true.
        if (out.length == 32) {
            uint256 r;
            assembly {
                r := mload(add(out, 0x20))
            }
            if (r == 0) revert NRX_ERC20_FALSE_RETURN();
            return out;
        }
        return out;
    }

    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, amount));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, amount));
    }

    function safeApprove(IERC20 token, address spender, uint256 amount) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, amount));
    }
}

abstract contract NimbrexReentrancyGuard {
    error NRX_REENTRANCY();
    uint256 private _nimbrexStatus = 1;

    modifier nonReentrant() {
        if (_nimbrexStatus != 1) revert NRX_REENTRANCY();
        _nimbrexStatus = 2;
        _;
        _nimbrexStatus = 1;
    }
}

abstract contract NimbrexPausable {
    error NRX_PAUSED();
    event NimbrexPauseSet(bool paused, uint64 at);

    bool public paused;

    modifier whenNotPaused() {
        if (paused) revert NRX_PAUSED();
        _;
    }

    function _setPaused(bool p) internal {
        paused = p;
        emit NimbrexPauseSet(p, uint64(block.timestamp));
    }
}

abstract contract NimbrexOwnable2Step {
    error NRX_NOT_OWNER();
    error NRX_NOT_PENDING_OWNER();
    error NRX_BAD_OWNER();

    event NimbrexOwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event NimbrexOwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    address public owner;
    address public pendingOwner;

    modifier onlyOwner() {
        if (msg.sender != owner) revert NRX_NOT_OWNER();
        _;
    }

    constructor(address initialOwner) {
        if (initialOwner == address(0)) revert NRX_BAD_OWNER();
        owner = initialOwner;
        emit NimbrexOwnershipTransferred(address(0), initialOwner);
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert NRX_BAD_OWNER();
        pendingOwner = newOwner;
        emit NimbrexOwnershipTransferStarted(owner, newOwner);
    }

    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NRX_NOT_PENDING_OWNER();
        address prev = owner;
        owner = msg.sender;
        pendingOwner = address(0);
        emit NimbrexOwnershipTransferred(prev, msg.sender);
    }
}

/// @notice Share token implemented inline to keep the vault self-contained.
contract NimbrexVaultShareToken {
    error NRX_SHARE_BAD_TO();
    error NRX_SHARE_BAD_FROM();
    error NRX_SHARE_INSUFF();
    error NRX_SHARE_ALLOWANCE();
    error NRX_SHARE_EXPIRED();
    error NRX_SHARE_BAD_SIG();

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    string public name;
    string public symbol;
    uint8 public immutable decimals;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // EIP-2612 Permit (EIP-712).
    bytes32 public immutable DOMAIN_SEPARATOR;
    bytes32 internal constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 internal constant _PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    mapping(address => uint256) public nonces;

    address public immutable vault;

    modifier onlyVault() {
        if (msg.sender != vault) revert NRX_SHARE_BAD_FROM();
        _;
    }

    constructor(address vault_, string memory name_, string memory symbol_, uint8 decimals_) {
        vault = vault_;
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
        DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name_)),
                keccak256(bytes("1")),
                block.chainid,
                address(this)
            )
        );
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transfer(address to, uint256 value) external returns (bool) {
        _transfer(msg.sender, to, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        if (a != type(uint256).max) {
            if (a < value) revert NRX_SHARE_ALLOWANCE();
            allowance[from][msg.sender] = a - value;
        }
        _transfer(from, to, value);
        return true;
    }

    function permit(
        address owner_,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (block.timestamp > deadline) revert NRX_SHARE_EXPIRED();
        uint256 nonce = nonces[owner_]++;
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(_PERMIT_TYPEHASH, owner_, spender, value, nonce, deadline))
            )
        );
        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != owner_) revert NRX_SHARE_BAD_SIG();
        allowance[owner_][spender] = value;
        emit Approval(owner_, spender, value);
    }

    function _transfer(address from, address to, uint256 value) internal {
        if (from == address(0)) revert NRX_SHARE_BAD_FROM();
        if (to == address(0)) revert NRX_SHARE_BAD_TO();
        uint256 bal = balanceOf[from];
        if (bal < value) revert NRX_SHARE_INSUFF();
        unchecked {
            balanceOf[from] = bal - value;
            balanceOf[to] += value;
        }
        emit Transfer(from, to, value);
    }

    function _mint(address to, uint256 value) external onlyVault {
        if (to == address(0)) revert NRX_SHARE_BAD_TO();
        totalSupply += value;
        unchecked {
            balanceOf[to] += value;
        }
        emit Transfer(address(0), to, value);
    }

    function _burn(address from, uint256 value) external onlyVault {
        if (from == address(0)) revert NRX_SHARE_BAD_FROM();
        uint256 bal = balanceOf[from];
        if (bal < value) revert NRX_SHARE_INSUFF();
        unchecked {
            balanceOf[from] = bal - value;
            totalSupply -= value;
        }
        emit Transfer(from, address(0), value);
    }

    /// @notice EIP-712 domain name digest helper for wallet wiring checks.
    function nameHash712() external view returns (bytes32) {
        return keccak256(bytes(name));
    }
}

/// @notice Main vault contract. Single-asset, multi-strategy.
contract NimbrexAIVault is NimbrexOwnable2Step, NimbrexReentrancyGuard, NimbrexPausable {
    using NimbrexSafeERC20 for IERC20;

    // ----- Errors (distinct prefix for uniqueness)
    error NRX_VAULT_BAD_ASSET();
    error NRX_VAULT_BAD_ADDR();
    error NRX_VAULT_ZERO();
    error NRX_VAULT_SLIPPAGE();
    error NRX_VAULT_CAP();
    error NRX_VAULT_STRAT_MISSING();
    error NRX_VAULT_STRAT_EXISTS();
    error NRX_VAULT_STRAT_DISABLED();
    error NRX_VAULT_DEBT_LIMIT();
    error NRX_VAULT_LOSS_LIMIT();
    error NRX_VAULT_COOLDOWN();
    error NRX_VAULT_ONLY_GUARDIAN();
    error NRX_VAULT_ONLY_ALLOCATOR();
    error NRX_VAULT_BAD_FEE();
    error NRX_VAULT_BAD_REPORT();
    error NRX_VAULT_SHARE_PULL();

    // ----- Events
    event NimbrexDeposit(address indexed caller, address indexed owner, uint256 assets, uint256 shares);
    event NimbrexWithdraw(address indexed caller, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);
    event NimbrexStrategyAdded(address indexed strategy, uint256 maxDebt);
    event NimbrexStrategyStatus(address indexed strategy, bool enabled);
    event NimbrexDebtUpdated(address indexed strategy, uint256 oldDebt, uint256 newDebt);
    event NimbrexHarvest(address indexed strategy, int256 pnl, uint256 totalAfter, uint256 feeSharesMinted);
    event NimbrexFeesUpdated(uint64 mgmtBpsPerYear, uint64 perfBps, address indexed feeRecipient);
    event NimbrexCapsUpdated(uint256 depositCap, uint256 maxTotalDebt);
    event NimbrexLossControls(uint64 maxLossBpsPerReport, uint64 reportCooldownSec);
    event NimbrexGuardianSet(address indexed oldGuardian, address indexed newGuardian);
    event NimbrexAllocatorSet(address indexed oldAllocator, address indexed newAllocator);
    event NimbrexSweep(address indexed token, address indexed to, uint256 amount);

    // ----- Immutable core
    IERC20 public immutable asset;
    uint8 public immutable assetDecimals;
    NimbrexVaultShareToken public immutable shares;

    // ----- Roles (constructor-set, standard pattern)
    address public guardian;
    address public allocator;
    address public feeRecipient;

    // ----- Parameters & accounting
    uint256 public depositCap;
    uint256 public maxTotalDebt;

    // Fees: mgmt fee accrues continuously against total assets (in bps/year)
    // and performance fee applies to positive PnL on reports.
    uint64 public mgmtFeeBpsPerYear;
    uint64 public performanceFeeBps;
    uint64 public maxLossBpsPerReport;
    uint64 public reportCooldownSec;

    uint64 public lastMgmtAccrual;
    uint256 public totalDebt;

    // Strategy state
    struct StrategyState {
        bool exists;
        bool enabled;
        uint64 lastReportAt;
        uint256 debt;
        uint256 maxDebt;
        uint256 totalReportedAssets;
        int256 cumulativePnl;
    }
    mapping(address => StrategyState) public strategy;
    address[] public strategyList;

    // Unique identifiers / domain tags (hex constants; no placeholders).
    bytes32 public constant PLATFORM_TAG =
        0x7eD4c91fA3b82c60e11f9c8b4a2f7e3d1c0a9b8f6e5d4c3b2a1908f7e6d5c4b3;
    bytes32 public constant RISK_POLICY_TAG =
        0x4Bc819e2f7a6d3c90581f4e2d9c0b7a5f8e3d1c6b9a4f7e2d5c8b1a4f7e2d9c0b;

    constructor(
        IERC20 asset_,
        string memory shareName,
        string memory shareSymbol,
        address owner_,
        address guardian_,
        address allocator_,
        address feeRecipient_,
        uint256 depositCap_,
        uint256 maxTotalDebt_,
        uint64 mgmtFeeBpsPerYear_,
        uint64 performanceFeeBps_,
        uint64 maxLossBpsPerReport_,
        uint64 reportCooldownSec_
    ) NimbrexOwnable2Step(owner_) {
        if (address(asset_) == address(0)) revert NRX_VAULT_BAD_ASSET();
        if (guardian_ == address(0) || allocator_ == address(0) || feeRecipient_ == address(0)) revert NRX_VAULT_BAD_ADDR();
        if (depositCap_ == 0 || maxTotalDebt_ == 0) revert NRX_VAULT_ZERO();
        if (mgmtFeeBpsPerYear_ > 2_000) revert NRX_VAULT_BAD_FEE(); // 20%/year hard ceiling
        if (performanceFeeBps_ > 5_000) revert NRX_VAULT_BAD_FEE(); // 50% hard ceiling
        if (maxLossBpsPerReport_ > 3_000) revert NRX_VAULT_BAD_FEE(); // 30% per report
        if (reportCooldownSec_ < 30) revert NRX_VAULT_BAD_FEE(); // avoid spam

        asset = asset_;
        uint8 dec = 18;
        // best-effort metadata read
        try IERC20Metadata(address(asset_)).decimals() returns (uint8 d) {
            dec = d;
