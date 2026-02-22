// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SECURE CONTRACT - Follows CEI Pattern
 *
 * This contract correctly follows Checks-Effects-Interactions.
 * SmartLint should NOT flag this.
 */
contract SecureBank {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    // SECURE: Effect before Interaction
    function withdraw() public {
        // Check
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // Effect BEFORE Interaction
        balances[msg.sender] = 0;

        // Interaction
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Transfer failed");
    }

    function getBalance() public view returns (uint256) {
        return address(this).balance;
    }
}
