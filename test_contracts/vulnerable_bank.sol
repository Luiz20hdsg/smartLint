// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * VULNERABLE CONTRACT - CEI Violation (Reentrancy)
 *
 * This contract violates the Checks-Effects-Interactions pattern:
 * it performs an external call (Interaction) before updating state (Effect).
 * SmartLint should flag this.
 */
contract VulnerableBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // VULNERABLE: Interaction before Effect
    function withdraw() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // Interaction BEFORE Effect — reentrancy risk!
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Transfer failed");

        // Effect AFTER Interaction — TOO LATE!
        balances[msg.sender] = 0;
    }

    // VULNERABLE: Another CEI violation with transfer
    function withdrawAll() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        payable(msg.sender).transfer(amount);

        balances[msg.sender] = 0;
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
