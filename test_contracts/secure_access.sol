// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SECURE CONTRACT - Proper Access Control
 *
 * All sensitive operations are protected with onlyOwner modifier
 * or require(msg.sender == owner) checks.
 * SmartLint should NOT flag this.
 */
contract SecureAccessControl {
    address public owner;
    uint256 public importantValue;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // SECURE: Protected by onlyOwner modifier
    function destroy() public onlyOwner {
        selfdestruct(payable(owner));
    }

    // SECURE: Protected by onlyOwner modifier
    function withdrawFunds() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    // SECURE: Protected by require check on msg.sender
    function changeOwner(address newOwner) public {
        require(msg.sender == owner, "Not authorized");
        owner = newOwner;
    }

    // SECURE: Protected by onlyOwner modifier
    function execute(address target, bytes calldata data) public onlyOwner {
        (bool success, ) = target.delegatecall(data);
        require(success);
    }

    function deposit() public payable {}
}
