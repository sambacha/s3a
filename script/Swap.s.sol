// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import "forge-std/console.sol";

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
}


// Interfaces (simplified for example)
interface IWETH is IERC20 {
    function deposit() external payable;
    function withdraw(uint wad) external;
}

interface IUniswapV2Router02 {
    function WETH() external pure returns (address);
    function swapExactETHForTokens(
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external payable returns (uint[] memory amounts);
}

contract SwapScript is Script {

    // Mainnet Addresses
    address constant WETH_ADDR = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC_ADDR = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant UNISWAP_V2_ROUTER = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;

    IWETH weth = IWETH(WETH_ADDR);
    IERC20 usdc = IERC20(USDC_ADDR);
    IUniswapV2Router02 router = IUniswapV2Router02(UNISWAP_V2_ROUTER);

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        address deployerAddress = vm.addr(deployerPrivateKey);

        // Amount of ETH to swap
        uint256 swapAmount = 0.1 ether;

        // Deal ETH to the deployer/sender address on the fork
        vm.deal(deployerAddress, swapAmount + 1 ether); // Add extra for gas

        vm.startBroadcast(deployerPrivateKey);

        console.log("Deployer ETH balance before:", deployerAddress.balance);
        console.log("Deployer USDC balance before:", usdc.balanceOf(deployerAddress));

        // Define swap path: ETH -> WETH -> USDC
        address[] memory path = new address[](2);
        path[0] = WETH_ADDR;
        path[1] = USDC_ADDR;

        // Execute the swap
        // amountOutMin = 0 for simplicity in this example
        // deadline = block.timestamp + some duration
        uint deadline = block.timestamp + 15 minutes;
        uint[] memory amounts = router.swapExactETHForTokens{value: swapAmount}(
            0,
            path,
            deployerAddress, // Send USDC back to deployer
            deadline
        );

        console.log("Swap executed.");
        console.log("Deployer ETH balance after:", deployerAddress.balance);
        console.log("Deployer WETH balance after:", weth.balanceOf(deployerAddress));
        console.log("Deployer USDC balance after:", usdc.balanceOf(deployerAddress));
        console.log("Received USDC amount:", amounts[1]); // amounts[0] is WETH spent, amounts[1] is USDC received

        vm.stopBroadcast();

        // Note: The transaction hash will be printed by the forge script command itself.
        // We don't need to explicitly log it here unless desired for other reasons.
    }
}
