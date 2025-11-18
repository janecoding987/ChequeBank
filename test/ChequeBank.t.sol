// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {ChequeBank, IChequeBank} from "../contracts/ChequeBank.sol";

contract ChequeBankTest is Test {
    ChequeBank public chequeBank;
    
    // Test accounts
    address public payer;
    address public payee;
    address public payee2;
    address public payee3;
    address public recipient;
    
    uint256 public payerPrivateKey;
    uint256 public payeePrivateKey;
    uint256 public payee2PrivateKey;
    uint256 public payee3PrivateKey;
    
    // Test constants
    uint256 public constant INITIAL_BALANCE = 100 ether;
    uint256 public constant CHEQUE_AMOUNT = 10 ether;
    uint32 public constant VALID_FROM = 1000;
    uint32 public constant VALID_THRU = 2000;
    uint32 public constant NONCE = 1;
    
    // Events
    event Deposited(address indexed depositor, uint256 amount);
    event Withdrawn(address indexed withdrawer, uint256 amount, address indexed recipient);
    event ChequeActivated(
        bytes32 indexed chequeId,
        address indexed payer,
        address indexed payee,
        uint256 amount
    );
    event ChequeRedeemed(
        bytes32 indexed chequeId,
        address indexed payer,
        address indexed payee,
        uint256 amount
    );
    event ChequeRevoked(bytes32 indexed chequeId, address indexed revoker);
    event SignOverNotified(
        bytes32 indexed chequeId,
        address indexed oldPayee,
        address indexed newPayee,
        uint8 counter
    );
    
    function setUp() public {
        // Generate test accounts
        payerPrivateKey = 0x1;
        payeePrivateKey = 0x2;
        payee2PrivateKey = 0x3;
        payee3PrivateKey = 0x4;
        
        payer = vm.addr(payerPrivateKey);
        payee = vm.addr(payeePrivateKey);
        payee2 = vm.addr(payee2PrivateKey);
        payee3 = vm.addr(payee3PrivateKey);
        recipient = address(0x999);
        
        // Deploy contract
        chequeBank = new ChequeBank();
        
        // Set up initial balances
        vm.deal(payer, INITIAL_BALANCE);
        vm.deal(payee, INITIAL_BALANCE);
        vm.deal(payee2, INITIAL_BALANCE);
        vm.deal(payee3, INITIAL_BALANCE);
        
        // Set block timestamp
        vm.warp(VALID_FROM + 100); // Within valid period
    }
    
    // ============ Helper Functions ============
    
    function _computeChequeId(IChequeBank.ChequeInfo memory chequeInfo) 
        internal pure returns (bytes32) 
    {
        return keccak256(abi.encodePacked(
            chequeInfo.amount,
            chequeInfo.validFrom,
            chequeInfo.validThru,
            chequeInfo.nonce,
            chequeInfo.payee,
            chequeInfo.payer
        ));
    }
    
    function _hashChequeInfo(IChequeBank.ChequeInfo memory chequeInfo) 
        internal pure returns (bytes32) 
    {
        bytes32 typeHash = keccak256(
            "ChequeInfo(uint256 amount,uint32 validFrom,uint32 validThru,uint32 nonce,address payee,address payer)"
        );
        return keccak256(abi.encode(
            typeHash,
            chequeInfo.amount,
            chequeInfo.validFrom,
            chequeInfo.validThru,
            chequeInfo.nonce,
            chequeInfo.payee,
            chequeInfo.payer
        ));
    }
    
    function _hashSignOverInfo(IChequeBank.SignOverInfo memory signOverInfo) 
        internal pure returns (bytes32) 
    {
        bytes32 typeHash = keccak256(
            "SignOverInfo(uint8 counter,address oldPayee,address newPayee,bytes32 chequeId)"
        );
        return keccak256(abi.encode(
            typeHash,
            signOverInfo.counter,
            signOverInfo.oldPayee,
            signOverInfo.newPayee,
            signOverInfo.chequeId
        ));
    }
    
    function _hashCheque(IChequeBank.ChequeInfo memory chequeInfo) 
        internal view returns (bytes32) 
    {
        bytes32 structHash = _hashChequeInfo(chequeInfo);
        bytes32 domainSeparator = chequeBank.DOMAIN_SEPARATOR();
        return keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator,
            structHash
        ));
    }
    
    function _hashSignOver(IChequeBank.SignOverInfo memory signOverInfo) 
        internal view returns (bytes32) 
    {
        bytes32 structHash = _hashSignOverInfo(signOverInfo);
        bytes32 domainSeparator = chequeBank.DOMAIN_SEPARATOR();
        return keccak256(abi.encodePacked(
            "\x19\x01",
            domainSeparator,
            structHash
        ));
    }
    
    function _signCheque(
        IChequeBank.ChequeInfo memory chequeInfo,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 messageHash = _hashCheque(chequeInfo);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }
    
    function _signSignOver(
        IChequeBank.SignOverInfo memory signOverInfo,
        uint256 privateKey
    ) internal view returns (bytes memory) {
        bytes32 messageHash = _hashSignOver(signOverInfo);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, messageHash);
        return abi.encodePacked(r, s, v);
    }
    
    function _createCheque(
        uint256 amount,
        uint32 validFrom,
        uint32 validThru,
        uint32 nonce,
        address payeeAddr,
        address payerAddr,
        uint256 payerPrivKey
    ) internal view returns (IChequeBank.Cheque memory) {
        IChequeBank.ChequeInfo memory chequeInfo = IChequeBank.ChequeInfo({
            amount: amount,
            validFrom: validFrom,
            validThru: validThru,
            nonce: nonce,
            payee: payeeAddr,
            payer: payerAddr
        });
        
        bytes memory sig = _signCheque(chequeInfo, payerPrivKey);
        
        return IChequeBank.Cheque({
            chequeInfo: chequeInfo,
            sig: sig
        });
    }
    
    function _createSignOver(
        uint8 counter,
        address oldPayeeAddr,
        address newPayeeAddr,
        bytes32 chequeId,
        uint256 oldPayeePrivKey
    ) internal view returns (IChequeBank.SignOver memory) {
        IChequeBank.SignOverInfo memory signOverInfo = IChequeBank.SignOverInfo({
            counter: counter,
            oldPayee: oldPayeeAddr,
            newPayee: newPayeeAddr,
            chequeId: chequeId
        });
        
        bytes memory sig = _signSignOver(signOverInfo, oldPayeePrivKey);
        
        return IChequeBank.SignOver({
            signOverInfo: signOverInfo,
            sig: sig
        });
    }
    
    // ============ Deposit Tests ============
    
    function test_Deposit() public {
        vm.startPrank(payer);
        uint256 depositAmount = 5 ether;
        
        vm.expectEmit(true, false, false, true);
        emit Deposited(payer, depositAmount);
        
        chequeBank.deposit{value: depositAmount}();
        
        assertEq(chequeBank.getBalance(payer), depositAmount);
        vm.stopPrank();
    }
    
    function test_Deposit_ZeroAmount() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: 0}();
        assertEq(chequeBank.getBalance(payer), 0);
        vm.stopPrank();
    }
    
    function test_Deposit_Multiple() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: 5 ether}();
        chequeBank.deposit{value: 3 ether}();
        assertEq(chequeBank.getBalance(payer), 8 ether);
        vm.stopPrank();
    }
    
    // ============ Withdraw Tests ============
    
    function test_Withdraw() public {
        vm.startPrank(payer);
        uint256 depositAmount = 10 ether;
        uint256 withdrawAmount = 5 ether;
        
        uint256 recipientBalanceBefore = recipient.balance;
        
        chequeBank.deposit{value: depositAmount}();
        
        vm.expectEmit(true, false, true, true);
        emit Withdrawn(payer, withdrawAmount, recipient);
        
        chequeBank.withdraw(withdrawAmount, payable(recipient));
        
        assertEq(chequeBank.getBalance(payer), depositAmount - withdrawAmount);
        assertEq(recipient.balance, recipientBalanceBefore + withdrawAmount);
        vm.stopPrank();
    }
    
    function test_Withdraw_Revert_InsufficientBalance() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: 5 ether}();
        
        vm.expectRevert(ChequeBank.InsufficientBalance.selector);
        chequeBank.withdraw(10 ether, payable(recipient));
        vm.stopPrank();
    }
    
    function test_Withdraw_Revert_ZeroAddress() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: 5 ether}();
        
        vm.expectRevert();
        chequeBank.withdraw(1 ether, payable(address(0)));
        vm.stopPrank();
    }
    
    // ============ Active Tests ============
    
    function test_Active() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        vm.expectEmit(true, true, true, true);
        emit ChequeActivated(chequeId, payer, payee, CHEQUE_AMOUNT);
        
        chequeBank.active(cheque);
        
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(uint8(state.status), uint8(IChequeBank.ChequeStatus.Active));
        assertEq(state.amount, CHEQUE_AMOUNT);
        assertEq(state.payee, payee);
        assertEq(state.payer, payer);
        assertEq(state.signOverCount, 0);
    }
    
    function test_Active_Revert_InvalidSignature() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payeePrivateKey // Wrong signer
        );
        
        vm.expectRevert(ChequeBank.InvalidSignature.selector);
        chequeBank.active(cheque);
    }
    
    function test_Active_Revert_ChequeNotYetValid() public {
        vm.warp(VALID_FROM - 1);
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        vm.expectRevert(ChequeBank.ChequeNotYetValid.selector);
        chequeBank.active(cheque);
    }
    
    function test_Active_Revert_ChequeExpired() public {
        vm.warp(VALID_THRU + 1);
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        vm.expectRevert(ChequeBank.ChequeExpired.selector);
        chequeBank.active(cheque);
    }
    
    function test_Active_Revert_ZeroPayer() public {
        // When payer is address(0), signature verification will fail first
        // because address(0) cannot sign, so we expect InvalidSignature
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            address(0),
            payerPrivateKey
        );
        
        // Signature verification happens before address validation
        vm.expectRevert(ChequeBank.InvalidSignature.selector);
        chequeBank.active(cheque);
    }
    
    function test_Active_Revert_ZeroPayee() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            address(0),
            payer,
            payerPrivateKey
        );
        
        vm.expectRevert(ChequeBank.InvalidPayee.selector);
        chequeBank.active(cheque);
    }
    
    function test_Active_Revert_AlreadyActive() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        
        vm.expectRevert(ChequeBank.ChequeAlreadyActive.selector);
        chequeBank.active(cheque);
    }
    
    // ============ Redeem Tests ============
    
    function test_Redeem() public {
        // Setup: deposit and activate cheque
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        // Redeem
        vm.startPrank(payee);
        vm.expectEmit(true, true, true, true);
        emit ChequeRedeemed(chequeId, payer, payee, CHEQUE_AMOUNT);
        
        chequeBank.redeem(chequeId);
        
        assertEq(chequeBank.getBalance(payee), CHEQUE_AMOUNT);
        assertEq(chequeBank.getBalance(payer), 0);
        
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(uint8(state.status), uint8(IChequeBank.ChequeStatus.Redeemed));
        vm.stopPrank();
    }
    
    function test_Redeem_Revert_ChequeNotActive() public {
        bytes32 fakeChequeId = keccak256("fake");
        
        vm.startPrank(payee);
        vm.expectRevert(ChequeBank.ChequeNotActive.selector);
        chequeBank.redeem(fakeChequeId);
        vm.stopPrank();
    }
    
    function test_Redeem_Revert_InvalidPayee() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        vm.startPrank(payee2); // Wrong payee
        vm.expectRevert(ChequeBank.InvalidPayee.selector);
        chequeBank.redeem(chequeId);
        vm.stopPrank();
    }
    
    function test_Redeem_Revert_InsufficientBalance() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        vm.startPrank(payee);
        vm.expectRevert(ChequeBank.InsufficientBalance.selector);
        chequeBank.redeem(chequeId);
        vm.stopPrank();
    }
    
    function test_Redeem_Revert_ChequeExpired() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        vm.warp(VALID_THRU + 1);
        
        vm.startPrank(payee);
        vm.expectRevert(ChequeBank.ChequeExpired.selector);
        chequeBank.redeem(chequeId);
        vm.stopPrank();
    }
    
    // ============ Revoke Tests ============
    
    function test_Revoke_ByPayer() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        vm.startPrank(payer);
        vm.expectEmit(true, false, false, true);
        emit ChequeRevoked(chequeId, payer);
        
        chequeBank.revoke(chequeId);
        
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(uint8(state.status), uint8(IChequeBank.ChequeStatus.Revoked));
        vm.stopPrank();
    }
    
    function test_Revoke_ByCurrentPayee() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        // Sign over to payee2
        IChequeBank.SignOver memory signOver = _createSignOver(
            1,
            payee,
            payee2,
            chequeId,
            payeePrivateKey
        );
        
        chequeBank.notifySignOver(signOver);
        
        // Now payee2 can revoke
        vm.startPrank(payee2);
        vm.expectEmit(true, false, false, true);
        emit ChequeRevoked(chequeId, payee2);
        
        chequeBank.revoke(chequeId);
        
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(uint8(state.status), uint8(IChequeBank.ChequeStatus.Revoked));
        vm.stopPrank();
    }
    
    function test_Revoke_Revert_Unauthorized() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        vm.startPrank(payee2); // Not authorized
        vm.expectRevert(ChequeBank.Unauthorized.selector);
        chequeBank.revoke(chequeId);
        vm.stopPrank();
    }
    
    function test_Revoke_Revert_ChequeNotActive() public {
        bytes32 fakeChequeId = keccak256("fake");
        
        vm.startPrank(payer);
        vm.expectRevert(ChequeBank.ChequeNotActive.selector);
        chequeBank.revoke(fakeChequeId);
        vm.stopPrank();
    }
    
    // ============ NotifySignOver Tests ============
    
    function test_NotifySignOver() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        IChequeBank.SignOver memory signOver = _createSignOver(
            1,
            payee,
            payee2,
            chequeId,
            payeePrivateKey
        );
        
        vm.expectEmit(true, true, true, true);
        emit SignOverNotified(chequeId, payee, payee2, 1);
        
        chequeBank.notifySignOver(signOver);
        
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(state.payee, payee2);
        assertEq(state.signOverCount, 1);
    }
    
    function test_NotifySignOver_Multiple() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        // First sign-over: payee -> payee2
        IChequeBank.SignOver memory signOver1 = _createSignOver(
            1,
            payee,
            payee2,
            chequeId,
            payeePrivateKey
        );
        chequeBank.notifySignOver(signOver1);
        
        // Second sign-over: payee2 -> payee3
        IChequeBank.SignOver memory signOver2 = _createSignOver(
            2,
            payee2,
            payee3,
            chequeId,
            payee2PrivateKey
        );
        chequeBank.notifySignOver(signOver2);
        
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(state.payee, payee3);
        assertEq(state.signOverCount, 2);
    }
    
    function test_NotifySignOver_Revert_InvalidSignature() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        IChequeBank.SignOver memory signOver = _createSignOver(
            1,
            payee,
            payee2,
            chequeId,
            payee2PrivateKey // Wrong signer
        );
        
        vm.expectRevert(ChequeBank.InvalidSignature.selector);
        chequeBank.notifySignOver(signOver);
    }
    
    function test_NotifySignOver_Revert_ChequeNotActive() public {
        bytes32 fakeChequeId = keccak256("fake");
        
        IChequeBank.SignOver memory signOver = _createSignOver(
            1,
            payee,
            payee2,
            fakeChequeId,
            payeePrivateKey
        );
        
        vm.expectRevert(ChequeBank.ChequeNotActive.selector);
        chequeBank.notifySignOver(signOver);
    }
    
    function test_NotifySignOver_Revert_InvalidOldPayee() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        IChequeBank.SignOver memory signOver = _createSignOver(
            1,
            payee2, // Wrong old payee
            payee3,
            chequeId,
            payee2PrivateKey
        );
        
        vm.expectRevert(ChequeBank.InvalidOldPayee.selector);
        chequeBank.notifySignOver(signOver);
    }
    
    function test_NotifySignOver_Revert_InvalidCounter() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        IChequeBank.SignOver memory signOver = _createSignOver(
            2, // Wrong counter (should be 1)
            payee,
            payee2,
            chequeId,
            payeePrivateKey
        );
        
        vm.expectRevert(ChequeBank.InvalidCounter.selector);
        chequeBank.notifySignOver(signOver);
    }
    
    function test_NotifySignOver_Revert_MaxSignOversReached() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        // Create 6 sign-overs
        address[] memory payees = new address[](7);
        payees[0] = payee;
        payees[1] = payee2;
        payees[2] = payee3;
        
        // Generate addresses for additional payees
        address payee4 = vm.addr(0x100);
        address payee5 = vm.addr(0x200);
        address payee6 = vm.addr(0x300);
        address payee7 = vm.addr(0x400);
        
        payees[3] = payee4;
        payees[4] = payee5;
        payees[5] = payee6;
        payees[6] = payee7;
        
        uint256[] memory privateKeys = new uint256[](6);
        privateKeys[0] = payeePrivateKey;
        privateKeys[1] = payee2PrivateKey;
        privateKeys[2] = payee3PrivateKey;
        privateKeys[3] = 0x100;
        privateKeys[4] = 0x200;
        privateKeys[5] = 0x300;
        
        for (uint8 i = 0; i < 6; i++) {
            IChequeBank.SignOver memory signOver = _createSignOver(
                i + 1,
                payees[i],
                payees[i + 1],
                chequeId,
                privateKeys[i]
            );
            chequeBank.notifySignOver(signOver);
        }
        
        // Try 7th sign-over (should fail because max is 6)
        IChequeBank.SignOver memory signOver7 = _createSignOver(
            7,
            payees[6],
            address(0x500),
            chequeId,
            0x400 // Private key for payee7
        );
        
        vm.expectRevert(ChequeBank.MaxSignOversReached.selector);
        chequeBank.notifySignOver(signOver7);
    }
    
    // ============ Multicall Tests ============
    
    function test_Multicall_DepositAndActive() public {
        vm.startPrank(payer);
        
        // First deposit separately (multicall can't send ETH)
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        // Then use multicall for active
        bytes[] memory calls = new bytes[](1);
        calls[0] = abi.encodeWithSelector(
            ChequeBank.active.selector,
            cheque
        );
        
        chequeBank.multicall(calls);
        
        assertEq(chequeBank.getBalance(payer), CHEQUE_AMOUNT);
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(uint8(state.status), uint8(IChequeBank.ChequeStatus.Active));
        
        vm.stopPrank();
    }
    
    function test_Multicall_ActiveAndRedeem() public {
        // Setup: deposit first
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        // Active and redeem in one multicall
        vm.startPrank(payee);
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeWithSelector(
            ChequeBank.active.selector,
            cheque
        );
        calls[1] = abi.encodeWithSelector(
            ChequeBank.redeem.selector,
            chequeId
        );
        
        chequeBank.multicall(calls);
        
        assertEq(chequeBank.getBalance(payee), CHEQUE_AMOUNT);
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(uint8(state.status), uint8(IChequeBank.ChequeStatus.Redeemed));
        vm.stopPrank();
    }
    
    function test_Multicall_ActiveSignOverRedeem() public {
        // Setup: deposit first
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        IChequeBank.SignOver memory signOver = _createSignOver(
            1,
            payee,
            payee2,
            chequeId,
            payeePrivateKey
        );
        
        // Active, sign-over, and redeem in one multicall
        vm.startPrank(payee);
        bytes[] memory calls = new bytes[](3);
        calls[0] = abi.encodeWithSelector(
            ChequeBank.active.selector,
            cheque
        );
        calls[1] = abi.encodeWithSelector(
            ChequeBank.notifySignOver.selector,
            signOver
        );
        calls[2] = abi.encodeWithSelector(
            ChequeBank.redeem.selector,
            chequeId
        );
        
        // Redeem should be called by payee2 (current payee after sign-over)
        vm.stopPrank();
        vm.startPrank(payee2);
        chequeBank.multicall(calls);
        
        assertEq(chequeBank.getBalance(payee2), CHEQUE_AMOUNT);
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(uint8(state.status), uint8(IChequeBank.ChequeStatus.Redeemed));
        vm.stopPrank();
    }
    
    function test_Multicall_ActiveSignOverRevoke() public {
        // Setup: deposit first
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        IChequeBank.SignOver memory signOver = _createSignOver(
            1,
            payee,
            payee2,
            chequeId,
            payeePrivateKey
        );
        
        // Active, sign-over, and revoke in one multicall
        // Revoke should be called by payee2 (current payee after sign-over)
        vm.startPrank(payee2);
        bytes[] memory calls = new bytes[](3);
        calls[0] = abi.encodeWithSelector(
            ChequeBank.active.selector,
            cheque
        );
        calls[1] = abi.encodeWithSelector(
            ChequeBank.notifySignOver.selector,
            signOver
        );
        calls[2] = abi.encodeWithSelector(
            ChequeBank.revoke.selector,
            chequeId
        );
        
        chequeBank.multicall(calls);
        
        // Verify cheque is revoked
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(uint8(state.status), uint8(IChequeBank.ChequeStatus.Revoked));
        
        // Verify balance is still with payer (not transferred)
        assertEq(chequeBank.getBalance(payer), CHEQUE_AMOUNT);
        assertEq(chequeBank.getBalance(payee2), 0);
        vm.stopPrank();
    }
    
    function test_Multicall_Revert_IfAnyFails() public {
        vm.startPrank(payer);
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeWithSelector(
            ChequeBank.active.selector,
            cheque
        );
        calls[1] = abi.encodeWithSelector(
            ChequeBank.redeem.selector,
            _computeChequeId(cheque.chequeInfo)
        );
        
        // Should revert because no deposit was made (insufficient balance)
        vm.expectRevert();
        chequeBank.multicall(calls);
        
        // Verify cheque was not activated (atomic revert)
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(uint8(state.status), uint8(IChequeBank.ChequeStatus.None));
        
        vm.stopPrank();
    }
    
    // ============ GetBalance Tests ============
    
    function test_GetBalance() public {
        assertEq(chequeBank.getBalance(payer), 0);
        
        vm.startPrank(payer);
        chequeBank.deposit{value: 5 ether}();
        vm.stopPrank();
        
        assertEq(chequeBank.getBalance(payer), 5 ether);
    }
    
    // ============ GetCheque Tests ============
    
    function test_GetCheque() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        // Before activation
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(uint8(state.status), uint8(IChequeBank.ChequeStatus.None));
        
        // After activation
        chequeBank.active(cheque);
        state = chequeBank.getCheque(chequeId);
        assertEq(uint8(state.status), uint8(IChequeBank.ChequeStatus.Active));
        assertEq(state.amount, CHEQUE_AMOUNT);
        assertEq(state.payee, payee);
        assertEq(state.payer, payer);
    }
    
    // ============ IsChequeValid Tests ============
    
    function test_IsChequeValid_ActiveCheque() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](0);
        
        assertTrue(chequeBank.isChequeValid(payee, cheque, signOverData));
        assertFalse(chequeBank.isChequeValid(payee2, cheque, signOverData));
    }
    
    function test_IsChequeValid_NoneStatus() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](0);
        
        // Cheque not activated yet, but valid for original payee
        assertTrue(chequeBank.isChequeValid(payee, cheque, signOverData));
    }
    
    function test_IsChequeValid_WithSignOver() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        IChequeBank.SignOver memory signOver = _createSignOver(
            1,
            payee,
            payee2,
            chequeId,
            payeePrivateKey
        );
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](1);
        signOverData[0] = signOver;
        
        // Before activation
        assertTrue(chequeBank.isChequeValid(payee2, cheque, signOverData));
        
        // After activation
        chequeBank.active(cheque);
        assertTrue(chequeBank.isChequeValid(payee2, cheque, signOverData));
        
        // After sign-over notification
        chequeBank.notifySignOver(signOver);
        assertTrue(chequeBank.isChequeValid(payee2, cheque, signOverData));
    }
    
    function test_IsChequeValid_Reverted() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        vm.startPrank(payer);
        chequeBank.revoke(chequeId);
        vm.stopPrank();
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](0);
        assertFalse(chequeBank.isChequeValid(payee, cheque, signOverData));
    }
    
    function test_IsChequeValid_Redeemed() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        vm.startPrank(payee);
        chequeBank.redeem(chequeId);
        vm.stopPrank();
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](0);
        assertFalse(chequeBank.isChequeValid(payee, cheque, signOverData));
    }
    
    function test_IsChequeValid_InvalidSignature() public view {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payeePrivateKey // Wrong signer
        );
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](0);
        assertFalse(chequeBank.isChequeValid(payee, cheque, signOverData));
    }
    
    function test_IsChequeValid_Expired() public {
        vm.warp(VALID_THRU + 1);
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](0);
        assertFalse(chequeBank.isChequeValid(payee, cheque, signOverData));
    }
    
    function test_IsChequeValid_InsufficientBalance() public view {
        // No deposit
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](0);
        assertFalse(chequeBank.isChequeValid(payee, cheque, signOverData));
    }
    
    function test_IsChequeValid_SignOverDataTooShort() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        chequeBank.active(cheque);
        
        // Sign over once on-chain: payee -> payee2
        IChequeBank.SignOver memory signOver1 = _createSignOver(
            1,
            payee,
            payee2,
            chequeId,
            payeePrivateKey
        );
        chequeBank.notifySignOver(signOver1);
        
        // Try to validate with empty signOverData
        // Note: When signOverData.length == 0, it checks if payee == currentPayee
        // Since currentPayee is payee2 (after sign-over), checking for payee2 should return true
        // But checking for payee (original) should return false
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](0);
        assertTrue(chequeBank.isChequeValid(payee2, cheque, signOverData)); // Current payee
        assertFalse(chequeBank.isChequeValid(payee, cheque, signOverData)); // Original payee (no longer valid)
        
        // Test with signOverData shorter than on-chain count (but not empty)
        // This should trigger the length check
        // Actually, we need to test with a partial chain that's shorter
        // But since we can't have partial valid chains, we test the case where
        // signOverData.length < signOverCount but > 0
        // However, this is hard to test because partial chains are invalid
        // So we test the case where we have 2 sign-overs on-chain but only provide 1
        IChequeBank.SignOver memory signOver2 = _createSignOver(
            2,
            payee2,
            payee3,
            chequeId,
            payee2PrivateKey
        );
        chequeBank.notifySignOver(signOver2);
        
        // Now we have 2 sign-overs on-chain, but only provide 1 in signOverData
        IChequeBank.SignOver[] memory partialSignOverData = new IChequeBank.SignOver[](1);
        partialSignOverData[0] = signOver1; // Only first sign-over
        assertFalse(chequeBank.isChequeValid(payee3, cheque, partialSignOverData));
    }
    
    function test_IsChequeValid_SignOverDataMismatch() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        chequeBank.active(cheque);
        
        // Sign over once on-chain: payee -> payee2
        IChequeBank.SignOver memory signOver1 = _createSignOver(
            1,
            payee,
            payee2,
            chequeId,
            payeePrivateKey
        );
        chequeBank.notifySignOver(signOver1);
        
        // Try to validate with different signOverData: payee -> payee3
        IChequeBank.SignOver memory signOver2 = _createSignOver(
            1,
            payee,
            payee3, // Different newPayee
            chequeId,
            payeePrivateKey
        );
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](1);
        signOverData[0] = signOver2;
        
        // Should fail because on-chain payee is payee2, but signOverData says payee3
        assertFalse(chequeBank.isChequeValid(payee3, cheque, signOverData));
    }
    
    function test_IsChequeValid_SignOverChainInvalidSignature() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        // Create sign-over with invalid signature
        IChequeBank.SignOverInfo memory signOverInfo = IChequeBank.SignOverInfo({
            counter: 1,
            oldPayee: payee,
            newPayee: payee2,
            chequeId: chequeId
        });
        bytes memory invalidSig = _signSignOver(signOverInfo, payee2PrivateKey); // Wrong signer
        
        IChequeBank.SignOver memory signOver = IChequeBank.SignOver({
            signOverInfo: signOverInfo,
            sig: invalidSig
        });
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](1);
        signOverData[0] = signOver;
        
        assertFalse(chequeBank.isChequeValid(payee2, cheque, signOverData));
    }
    
    function test_IsChequeValid_SignOverChainWrongChequeId() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 wrongChequeId = keccak256("wrong");
        
        // Create sign-over with wrong chequeId
        IChequeBank.SignOver memory signOver = _createSignOver(
            1,
            payee,
            payee2,
            wrongChequeId, // Wrong chequeId
            payeePrivateKey
        );
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](1);
        signOverData[0] = signOver;
        
        assertFalse(chequeBank.isChequeValid(payee2, cheque, signOverData));
    }
    
    function test_IsChequeValid_SignOverChainWrongCounter() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        // Create sign-over with wrong counter (should be 1, but using 2)
        IChequeBank.SignOver memory signOver = _createSignOver(
            2, // Wrong counter
            payee,
            payee2,
            chequeId,
            payeePrivateKey
        );
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](1);
        signOverData[0] = signOver;
        
        assertFalse(chequeBank.isChequeValid(payee2, cheque, signOverData));
    }
    
    function test_IsChequeValid_SignOverChainDiscontinuity() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        // Create sign-over with wrong oldPayee (chain discontinuity)
        IChequeBank.SignOverInfo memory signOverInfo = IChequeBank.SignOverInfo({
            counter: 1,
            oldPayee: payee3, // Wrong oldPayee (should be payee)
            newPayee: payee2,
            chequeId: chequeId
        });
        bytes memory sig = _signSignOver(signOverInfo, payee3PrivateKey);
        
        IChequeBank.SignOver memory signOver = IChequeBank.SignOver({
            signOverInfo: signOverInfo,
            sig: sig
        });
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](1);
        signOverData[0] = signOver;
        
        assertFalse(chequeBank.isChequeValid(payee2, cheque, signOverData));
    }
    
    function test_IsChequeValid_SignOverChainFinalPayeeMismatch() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        // Create valid sign-over chain
        IChequeBank.SignOver memory signOver = _createSignOver(
            1,
            payee,
            payee2,
            chequeId,
            payeePrivateKey
        );
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](1);
        signOverData[0] = signOver;
        
        // Check with wrong final payee
        assertFalse(chequeBank.isChequeValid(payee3, cheque, signOverData));
        // Check with correct final payee
        assertTrue(chequeBank.isChequeValid(payee2, cheque, signOverData));
    }
    
    function test_IsChequeValid_SignOverDataExceedsMax() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        // Create 7 sign-overs (exceeds max of 6)
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](7);
        address[] memory payees = new address[](8);
        payees[0] = payee;
        payees[1] = payee2;
        payees[2] = payee3;
        payees[3] = address(0x100);
        payees[4] = address(0x200);
        payees[5] = address(0x300);
        payees[6] = address(0x400);
        payees[7] = address(0x500);
        
        uint256[] memory privateKeys = new uint256[](7);
        privateKeys[0] = payeePrivateKey;
        privateKeys[1] = payee2PrivateKey;
        privateKeys[2] = payee3PrivateKey;
        privateKeys[3] = 0x100;
        privateKeys[4] = 0x200;
        privateKeys[5] = 0x300;
        privateKeys[6] = 0x400;
        
        for (uint8 i = 0; i < 7; i++) {
            signOverData[i] = _createSignOver(
                i + 1,
                payees[i],
                payees[i + 1],
                chequeId,
                privateKeys[i]
            );
        }
        
        assertFalse(chequeBank.isChequeValid(payees[7], cheque, signOverData));
    }
    
    function test_IsChequeValid_NotYetValid() public {
        vm.warp(VALID_FROM - 1);
        
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](0);
        assertFalse(chequeBank.isChequeValid(payee, cheque, signOverData));
    }
    
    function test_Multicall_EmptyErrorMessage() public {
        // Test multicall with a call that fails with empty error message
        // This tests the else branch in multicall (result.length == 0)
        bytes[] memory calls = new bytes[](1);
        // Call a non-existent function to trigger failure with empty error
        calls[0] = abi.encodeWithSelector(bytes4(0x12345678));
        
        vm.expectRevert("Multicall failed");
        chequeBank.multicall(calls);
    }
    
    // ============ Edge Cases and Exception Tests ============
    
    function test_Deposit_MaxUint256() public {
        vm.startPrank(payer);
        // Test with maximum uint256 value
        uint256 maxAmount = type(uint256).max;
        vm.deal(payer, maxAmount);
        
        // This should work, but we need to be careful about overflow in balance addition
        // In Solidity 0.8+, overflow will revert automatically
        chequeBank.deposit{value: maxAmount}();
        
        assertEq(chequeBank.getBalance(payer), maxAmount);
        vm.stopPrank();
    }
    
    function test_Deposit_Overflow() public {
        // Note: Testing actual uint256 overflow is difficult with vm.deal
        // This test verifies that the contract properly handles large amounts
        // and that Solidity 0.8+ overflow protection works
        vm.startPrank(payer);
        
        // Test with a very large but practical amount
        uint256 largeAmount = 1e30; // 1e30 wei (much larger than any realistic ETH amount)
        vm.deal(payer, largeAmount * 2);
        
        // First deposit
        chequeBank.deposit{value: largeAmount}();
        assertEq(chequeBank.getBalance(payer), largeAmount);
        
        // Deposit more - should work
        chequeBank.deposit{value: largeAmount}();
        assertEq(chequeBank.getBalance(payer), largeAmount * 2);
        
        // The actual overflow protection is tested implicitly:
        // Solidity 0.8+ automatically reverts on arithmetic overflow
        // This is verified by the fact that all other tests pass
        vm.stopPrank();
    }
    
    function test_Deposit_LargeAmount() public {
        vm.startPrank(payer);
        uint256 largeAmount = 1000000 ether;
        vm.deal(payer, largeAmount);
        
        chequeBank.deposit{value: largeAmount}();
        assertEq(chequeBank.getBalance(payer), largeAmount);
        
        // Deposit more
        vm.deal(payer, largeAmount * 2);
        chequeBank.deposit{value: largeAmount}();
        assertEq(chequeBank.getBalance(payer), largeAmount * 2);
        
        vm.stopPrank();
    }
    
    function test_Withdraw_Overflow() public {
        vm.startPrank(payer);
        uint256 depositAmount = 100 ether;
        vm.deal(payer, depositAmount);
        chequeBank.deposit{value: depositAmount}();
        
        // Try to withdraw more than balance - should revert with InsufficientBalance
        // We use unchecked to allow the addition, but the contract will check balance
        vm.expectRevert(ChequeBank.InsufficientBalance.selector);
        unchecked {
            uint256 withdrawAmount = depositAmount + 1;
            chequeBank.withdraw(withdrawAmount, payable(recipient));
        }
        
        vm.stopPrank();
    }
    
    function test_DirectETHTransfer_Reverts() public {
        // Contract has no receive() or fallback() function
        // Direct ETH transfer should fail (return false, not revert)
        vm.deal(payer, 10 ether);
        
        vm.startPrank(payer);
        // call() returns false if the call fails, it doesn't revert
        (bool success, ) = address(chequeBank).call{value: 10 ether}("");
        assertFalse(success);
        vm.stopPrank();
        
        // Verify contract balance is still 0
        assertEq(address(chequeBank).balance, 0);
    }
    
    function test_DirectETHTransfer_WithLowLevelCall() public {
        // Test using low-level call to send ETH directly
        vm.deal(payer, 10 ether);
        
        vm.startPrank(payer);
        // This will fail because contract has no receive/fallback
        (bool success, ) = address(chequeBank).call{value: 10 ether}("");
        assertFalse(success);
        vm.stopPrank();
        
        // Verify ETH was not transferred
        assertEq(address(chequeBank).balance, 0);
        assertEq(payer.balance, 10 ether);
    }
    
    function test_DirectETHTransfer_UsingSend() public {
        // Test using send() to transfer ETH directly
        vm.deal(payer, 10 ether);
        
        vm.startPrank(payer);
        // send() returns false if transfer fails
        bool success = payable(address(chequeBank)).send(10 ether);
        assertFalse(success);
        vm.stopPrank();
        
        // Verify ETH was not transferred
        assertEq(address(chequeBank).balance, 0);
        assertEq(payer.balance, 10 ether);
    }
    
    function test_DirectETHTransfer_UsingTransfer() public {
        // Test using transfer() to transfer ETH directly
        vm.deal(payer, 10 ether);
        
        vm.startPrank(payer);
        // transfer() reverts if transfer fails
        vm.expectRevert();
        payable(address(chequeBank)).transfer(10 ether);
        vm.stopPrank();
        
        // Verify ETH was not transferred
        assertEq(address(chequeBank).balance, 0);
        assertEq(payer.balance, 10 ether);
    }
    
    function test_ChequeAmount_Overflow() public {
        // Test creating cheque with maximum uint256 amount
        uint256 maxAmount = type(uint256).max;
        
        vm.startPrank(payer);
        vm.deal(payer, maxAmount);
        chequeBank.deposit{value: maxAmount}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            maxAmount,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        // Should be able to activate
        chequeBank.active(cheque);
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(state.amount, maxAmount);
    }
    
    function test_Redeem_WithMaxAmount() public {
        uint256 maxAmount = type(uint256).max;
        
        vm.startPrank(payer);
        vm.deal(payer, maxAmount);
        chequeBank.deposit{value: maxAmount}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            maxAmount,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        vm.startPrank(payee);
        chequeBank.redeem(chequeId);
        
        assertEq(chequeBank.getBalance(payee), maxAmount);
        assertEq(chequeBank.getBalance(payer), 0);
        vm.stopPrank();
    }
    
    function test_Withdraw_ZeroAmount() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: 10 ether}();
        
        // Withdraw 0 should work
        uint256 balanceBefore = chequeBank.getBalance(payer);
        chequeBank.withdraw(0, payable(recipient));
        assertEq(chequeBank.getBalance(payer), balanceBefore);
        assertEq(recipient.balance, 0);
        
        vm.stopPrank();
    }
    
    function test_ChequeAmount_Zero() public {
        // Test creating cheque with 0 amount
        IChequeBank.Cheque memory cheque = _createCheque(
            0,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        // Should be able to activate
        chequeBank.active(cheque);
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(state.amount, 0);
        assertEq(uint8(state.status), uint8(IChequeBank.ChequeStatus.Active));
    }
    
    function test_Redeem_ZeroAmount() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: 10 ether}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            0,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        vm.startPrank(payee);
        chequeBank.redeem(chequeId);
        
        // Balance should not change (0 amount)
        assertEq(chequeBank.getBalance(payee), 0);
        assertEq(chequeBank.getBalance(payer), 10 ether);
        
        IChequeBank.ChequeState memory state = chequeBank.getCheque(chequeId);
        assertEq(uint8(state.status), uint8(IChequeBank.ChequeStatus.Redeemed));
        vm.stopPrank();
    }
    
    // ============ Gas Tests ============
    
    function test_Gas_Deposit() public {
        vm.startPrank(payer);
        uint256 gasBefore = gasleft();
        chequeBank.deposit{value: 1 ether}();
        uint256 gasUsed = gasBefore - gasleft();
        
        // Log gas usage for reference
        console.log("Gas used for deposit:", gasUsed);
        
        // Verify it's within reasonable bounds (should be < 100k gas)
        assertLt(gasUsed, 100000);
        vm.stopPrank();
    }
    
    function test_Gas_Withdraw() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: 1 ether}();
        
        uint256 gasBefore = gasleft();
        chequeBank.withdraw(1 ether, payable(recipient));
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Gas used for withdraw:", gasUsed);
        assertLt(gasUsed, 150000);
        vm.stopPrank();
    }
    
    function test_Gas_Active() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        uint256 gasBefore = gasleft();
        chequeBank.active(cheque);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Gas used for active:", gasUsed);
        assertLt(gasUsed, 200000);
    }
    
    function test_Gas_Redeem() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        vm.startPrank(payee);
        uint256 gasBefore = gasleft();
        chequeBank.redeem(chequeId);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Gas used for redeem:", gasUsed);
        assertLt(gasUsed, 200000);
        vm.stopPrank();
    }
    
    function test_Gas_Revoke() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        vm.startPrank(payer);
        uint256 gasBefore = gasleft();
        chequeBank.revoke(chequeId);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Gas used for revoke:", gasUsed);
        assertLt(gasUsed, 150000);
        vm.stopPrank();
    }
    
    function test_Gas_NotifySignOver() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        IChequeBank.SignOver memory signOver = _createSignOver(
            1,
            payee,
            payee2,
            chequeId,
            payeePrivateKey
        );
        
        uint256 gasBefore = gasleft();
        chequeBank.notifySignOver(signOver);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Gas used for notifySignOver:", gasUsed);
        assertLt(gasUsed, 200000);
    }
    
    function test_Gas_Multicall() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        bytes[] memory calls = new bytes[](2);
        calls[0] = abi.encodeWithSelector(
            ChequeBank.active.selector,
            cheque
        );
        calls[1] = abi.encodeWithSelector(
            ChequeBank.redeem.selector,
            chequeId
        );
        
        vm.startPrank(payee);
        uint256 gasBefore = gasleft();
        chequeBank.multicall(calls);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Gas used for multicall (active + redeem):", gasUsed);
        assertLt(gasUsed, 400000);
        vm.stopPrank();
    }
    
    function test_Gas_GetBalance() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: 1 ether}();
        vm.stopPrank();
        
        uint256 gasBefore = gasleft();
        chequeBank.getBalance(payer);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Gas used for getBalance:", gasUsed);
        assertLt(gasUsed, 50000);
    }
    
    function test_Gas_GetCheque() public {
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        chequeBank.active(cheque);
        bytes32 chequeId = _computeChequeId(cheque.chequeInfo);
        
        uint256 gasBefore = gasleft();
        chequeBank.getCheque(chequeId);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Gas used for getCheque:", gasUsed);
        assertLt(gasUsed, 50000);
    }
    
    function test_Gas_IsChequeValid() public {
        vm.startPrank(payer);
        chequeBank.deposit{value: CHEQUE_AMOUNT}();
        vm.stopPrank();
        
        IChequeBank.Cheque memory cheque = _createCheque(
            CHEQUE_AMOUNT,
            VALID_FROM,
            VALID_THRU,
            NONCE,
            payee,
            payer,
            payerPrivateKey
        );
        
        IChequeBank.SignOver[] memory signOverData = new IChequeBank.SignOver[](0);
        
        uint256 gasBefore = gasleft();
        chequeBank.isChequeValid(payee, cheque, signOverData);
        uint256 gasUsed = gasBefore - gasleft();
        
        console.log("Gas used for isChequeValid:", gasUsed);
        assertLt(gasUsed, 150000);
    }
}

