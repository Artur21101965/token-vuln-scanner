// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

interface IENS {
    function owner(bytes32 node) external view returns (address);
    function setOwner(bytes32 node, address owner) external;
    function setSubnodeOwner(bytes32 node, bytes32 label, address owner) external;
    function resolver(bytes32 node) external view returns (address);
    function setResolver(bytes32 node, address resolver) external;
    function ttl(bytes32 node) external view returns (uint64);
}

contract ENSFuzzTest is Test {
    IENS public constant ENS_REGISTRY = IENS(0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e);
    address public constant ENS_CONTROLLER = 0x253553366Da8546fC250F225fe3d25d0C782303b;
    address public constant ATTACKER = address(0xBEEF);
    
    // Invariant 1: Attacker should never be able to steal .eth name ownership
    function testFuzz_cannotStealETHName(bytes32 node) public {
        vm.assume(node != bytes32(0));
        vm.assume(ENS_REGISTRY.owner(node) != ATTACKER);
        vm.assume(ENS_REGISTRY.owner(node) != address(0));
        
        vm.prank(ATTACKER);
        try ENS_REGISTRY.setOwner(node, ATTACKER) {
            assert(ENS_REGISTRY.owner(node) != ATTACKER);
        } catch {
            // Expected - should revert
        }
    }
    
    // Invariant 2: Controller ETH balance should only decrease via owner
    function testFuzz_controllerCannotBeDrainedByAnyone() public {
        uint256 balBefore = ENS_CONTROLLER.balance;
        vm.prank(ATTACKER);
        
        // Try to call withdraw() if it exists
        (bool success, ) = ENS_CONTROLLER.call(abi.encodeWithSignature("withdraw()"));
        
        // If it succeeded, attacker shouldn't get ETH
        if (success) {
            assertEq(ENS_CONTROLLER.balance, balBefore);
        }
    }
    
    // Invariant 3: Random address can't register .eth without payment
    function testFuzz_cannotRegisterFree(bytes32 commitment, string memory name, uint256 duration) public {
        vm.assume(duration > 0 && duration < 36500 days);
        vm.assume(bytes(name).length > 0);
        
        // Check if registration without commit works
        (bool success,) = ENS_CONTROLLER.call(
            abi.encodeWithSignature("register(string,address,uint256,bytes32)", name, ATTACKER, duration, commitment)
        );
        assertFalse(success);
    }
}
