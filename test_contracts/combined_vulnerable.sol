// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * COMBINED VULNERABLE CONTRACT - Multiple issues
 *
 * This contract has ALL THREE vulnerability types for a comprehensive test.
 */
contract CombinedVulnerable {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULN 1: CEI Violation — state change after external call
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0);

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent);

        balances[msg.sender] = 0;  // Too late!
    }

    // VULN 2: Missing access control on sensitive operation
    function emergencyWithdraw() public {
        payable(msg.sender).transfer(address(this).balance);
    }

    // VULN 3: Unchecked low-level call
    function forwardCall(address target, bytes calldata data) public {
        target.call(data);  // Return value discarded!
    }

    // VULN 2+3: Missing access control AND unchecked delegatecall
    function upgradeAndCall(address newImpl, bytes calldata data) public {
        newImpl.delegatecall(data);
    }

    // SAFE: This function is clean
    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
