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
