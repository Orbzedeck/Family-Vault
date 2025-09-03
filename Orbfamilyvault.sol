// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol"; // ✅ v0.8.x compatible
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract OrbVault is ReentrancyGuard, Ownable {
    using SafeERC20 for IERC20;

    struct Beneficiary {
        address account;
        uint256 percentage; // in basis points (10000 = 100%)
    }

    uint256 public inactivityPeriod;
    uint256 public lastAlivePing;
    Beneficiary[] public beneficiaries;

    mapping(address => bool) private isBeneficiary; // prevent duplicates
    mapping(bytes32 => bool) public claimed; // prevent double-claims

    bytes32 public merkleRoot; // Optional for external claims
    bool public emergencyUnlocked;

    event AlivePing(address indexed owner, uint256 timestamp);
    event Deposit(address indexed from, uint256 amount, address token);
    event Withdraw(address indexed to, uint256 amount, address token);
    event EmergencyUnlocked(uint256 timestamp);
    event BeneficiaryAdded(address indexed account, uint256 percentage);
    event BeneficiaryRemoved(address indexed account);
    event BeneficiaryUpdated(address indexed account, uint256 newPercentage);
    event Claimed(address indexed to, uint256 amount);

    modifier onlyInactiveOwner() {
        require(block.timestamp > lastAlivePing + inactivityPeriod, "Owner still active");
        _;
    }

    constructor(uint256 _inactivityPeriod) Ownable(msg.sender) {
        inactivityPeriod = _inactivityPeriod;
        lastAlivePing = block.timestamp;
    }

    // ---- Owner activity ----
    function alivePing() external onlyOwner {
        lastAlivePing = block.timestamp;
        emit AlivePing(msg.sender, block.timestamp);
    }

    // ---- Deposit ----
    receive() external payable {
        emit Deposit(msg.sender, msg.value, address(0));
    }

    function depositToken(address token, uint256 amount) external {
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        emit Deposit(msg.sender, amount, token);
    }

    // ---- Withdraw (Owner only while active) ----
    function withdrawETH(uint256 amount) external onlyOwner nonReentrant {
        require(address(this).balance >= amount, "Insufficient ETH");
        (bool success, ) = payable(owner()).call{value: amount}("");
        require(success, "ETH transfer failed");
        emit Withdraw(owner(), amount, address(0));
    }

    function withdrawToken(address token, uint256 amount) external onlyOwner nonReentrant {
        IERC20(token).safeTransfer(owner(), amount);
        emit Withdraw(owner(), amount, token);
    }

    // ---- Beneficiaries ----
    function addBeneficiary(address account, uint256 percentage) external onlyOwner {
        require(account != address(0), "Invalid address");
        require(!isBeneficiary[account], "Already added");
        beneficiaries.push(Beneficiary(account, percentage));
        isBeneficiary[account] = true;
        emit BeneficiaryAdded(account, percentage);
    }

    function updateBeneficiary(address account, uint256 newPercentage) external onlyOwner {
        require(isBeneficiary[account], "Not a beneficiary");
        for (uint i = 0; i < beneficiaries.length; i++) {
            if (beneficiaries[i].account == account) {
                beneficiaries[i].percentage = newPercentage;
                emit BeneficiaryUpdated(account, newPercentage);
                break;
            }
        }
    }

    function removeBeneficiary(address account) external onlyOwner {
        require(isBeneficiary[account], "Not a beneficiary");
        for (uint i = 0; i < beneficiaries.length; i++) {
            if (beneficiaries[i].account == account) {
                beneficiaries[i] = beneficiaries[beneficiaries.length - 1];
                beneficiaries.pop();
                break;
            }
        }
        isBeneficiary[account] = false;
        emit BeneficiaryRemoved(account);
    }

    // ---- Emergency Unlock ----
    function emergencyUnlock() external onlyInactiveOwner {
        emergencyUnlocked = true;
        emit EmergencyUnlocked(block.timestamp);
    }

    function distributeETH() external nonReentrant {
        require(emergencyUnlocked, "Not unlocked");
        uint256 totalBalance = address(this).balance;
        uint256 distributed;
        for (uint i = 0; i < beneficiaries.length; i++) {
            uint256 share = (totalBalance * beneficiaries[i].percentage) / 10000;
            distributed += share;
            (bool success, ) = payable(beneficiaries[i].account).call{value: share}("");
            require(success, "ETH transfer failed");
        }
        // handle dust (send remainder to last beneficiary if any)
        if (distributed < totalBalance && beneficiaries.length > 0) {
            uint256 remainder = totalBalance - distributed;
            (bool success, ) = payable(beneficiaries[beneficiaries.length - 1].account).call{value: remainder}("");
            require(success, "Dust transfer failed");
        }
    }

    function distributeToken(address token) external nonReentrant {
        require(emergencyUnlocked, "Not unlocked");
        uint256 totalBalance = IERC20(token).balanceOf(address(this));
        uint256 distributed;
        for (uint i = 0; i < beneficiaries.length; i++) {
            uint256 share = (totalBalance * beneficiaries[i].percentage) / 10000;
            distributed += share;
            IERC20(token).safeTransfer(beneficiaries[i].account, share);
        }
        // handle dust
        if (distributed < totalBalance && beneficiaries.length > 0) {
            uint256 remainder = totalBalance - distributed;
            IERC20(token).safeTransfer(beneficiaries[beneficiaries.length - 1].account, remainder);
        }
    }

    // ---- Merkle Claim (Optional) ----
    function setMerkleRoot(bytes32 root) external onlyOwner {
        merkleRoot = root;
    }

    function claim(bytes32[] calldata proof, uint256 amount) external nonReentrant {
        require(emergencyUnlocked, "Not unlocked");
        bytes32 leaf = keccak256(abi.encodePacked(msg.sender, amount));
        require(MerkleProof.verify(proof, merkleRoot, leaf), "Invalid proof");
        require(!claimed[leaf], "Already claimed");
        claimed[leaf] = true;
        (bool success, ) = payable(msg.sender).call{value: amount}("");
        require(success, "ETH transfer failed");
        emit Claimed(msg.sender, amount);
    }
}
