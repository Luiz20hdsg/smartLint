// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * VULNERABLE CONTRACT - Unchecked External Calls
 *
 * Low-level calls whose return values are not checked.
 * SmartLint should flag these.
 */
contract VulnerableUncheckedCalls {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: call return value completely discarded
    function sendEther(address payable recipient) public {
        recipient.call{value: 1 ether}("");
    }

    // VULNERABLE: send return value not checked
    function sendWithSend(address payable recipient) public {
        recipient.send(1 ether);
    }

    // VULNERABLE: delegatecall return value discarded
    function executeDelegateCall(address target, bytes calldata data) public {
        target.delegatecall(data);
    }

    // SAFE: return value is checked with require
    function safeSend(address payable recipient, uint256 amount) public {
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // SAFE: return value is checked with if
    function safeSendWithIf(address payable recipient, uint256 amount) public {
        (bool success, ) = recipient.call{value: amount}("");
        if (!success) {
            revert("Transfer failed");
        }
    }

    receive() external payable {}
}
