// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * VULNERABLE CONTRACT - Missing Access Control
 *
 * Critical functions like selfdestruct, ether withdrawal, and owner changes
 * have no access control modifiers or msg.sender checks.
 * SmartLint should flag all of these.
 */
contract VulnerableAccessControl {
    address public owner;
    uint256 public importantValue;

    constructor() {
        owner = msg.sender;
    }

    // VULNERABLE: No access control on selfdestruct
    function destroy() public {
        selfdestruct(payable(msg.sender));
    }

    // VULNERABLE: No access control on ether withdrawal to arbitrary address
    function withdrawFunds(address payable recipient) public {
        recipient.transfer(address(this).balance);
    }

    // VULNERABLE: No access control on owner change
    function changeOwner(address newOwner) public {
        owner = newOwner;
    }

    // VULNERABLE: No access control on delegatecall
    function execute(address target, bytes calldata data) public {
        (bool success, ) = target.delegatecall(data);
        require(success);
    }

    // SAFE: This is just a view function, no sensitive op
    function getOwner() public view returns (address) {
        return owner;
    }

    // SAFE: Deposit is not a sensitive operation
    function deposit() public payable {}
}
