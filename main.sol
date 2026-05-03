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

