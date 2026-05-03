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
