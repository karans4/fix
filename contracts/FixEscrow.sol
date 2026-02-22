// SPDX-License-Identifier: AGPL-3.0-or-later
// FixEscrow — neutral on-chain escrow for fix contracts
//
// The contract is a dumb escrow machine. It holds money, enforces state
// transitions, and routes funds based on outcomes. It doesn't know about
// platform fees — the platform takes its cut off-chain before posting.
//
// Flow:
//   1. Principal sends (bounty + courtFees + platformFee) to platform
//   2. Platform keeps platformFee, calls post() with (bounty + courtFees)
//   3. Contract holds escrow. All payouts go directly to principal/agent addresses.
//
// Anyone can post directly (skip the platform), but good luck finding agents.
//
// Court fees are CUMULATIVE across tiers. Full appeal chain = entire bond.
pragma solidity ^0.8.24;

contract FixEscrow {

    // ══════════════════════════════════════════════════════════════
    //  TYPES
    // ══════════════════════════════════════════════════════════════

    enum Status {
        Open,           // 0  waiting for agent
        Investigating,  // 1  agent bonded, inspecting
        InProgress,     // 2  agent working on fix
        Review,         // 3  autonomous: fix submitted, review window ticking
        AwaitResponse,  // 4  dispute filed, counter-argue window
        Disputed,       // 5  awaiting oracle ruling
        Ruled,          // 6  ruling posted, appeal window open
        Halted,         // 7  emergency halt → immediate judge
        Fulfilled,      // 8  terminal — agent paid
        Canceled,       // 9  terminal — principal refunded
        Voided          // 10 terminal — oracle no-show, funds returned
    }

    enum Ruling {
        Fulfilled,      // agent's fix worked
        Canceled,       // fix failed / agent at fault
        Impossible      // task can't be done, filer pays court costs
    }

    uint8 constant EVIL_AGENT     = 1;
    uint8 constant EVIL_PRINCIPAL = 2;

    // ══════════════════════════════════════════════════════════════
    //  PROTOCOL CONSTANTS (timing + ratios only, no prices)
    // ══════════════════════════════════════════════════════════════

    uint256 public constant GRACE_PERIOD         = 30;     // seconds — free backout window
    uint256 public constant RESPONSE_WINDOW      = 30;     // seconds to respond to dispute
    uint256 public constant RULING_TIMEOUT       = 60;     // seconds for oracle to rule
    uint256 public constant APPEAL_WINDOW        = 30;     // seconds to appeal after ruling
    uint256 public constant ABANDONMENT_TIMEOUT  = 120;    // seconds of silence = abandoned
    uint256 public constant PICKUP_TIMEOUT       = 30;     // seconds before stale

    // ══════════════════════════════════════════════════════════════
    //  PER-CONTRACT STATE
    // ══════════════════════════════════════════════════════════════

    struct Contract {
        // Parties
        address principal;              // who posted (can be platform on behalf of user)
        address agent;

        // Roles (set at creation)
        address platform;               // for bond approval signatures
        address oracle;                 // runs judges
        address charity;                // receives evil party's funds

        // Money (everything in the contract — platform fee already taken)
        uint256 bounty;
        uint256 principalBond;          // = sum(courtFees)
        uint256 agentBond;
        uint256 minBond;
        uint256 cancelFee;              // = platform fee that was already taken (used as backout penalty)
        uint256[3] courtFees;           // per-tier oracle fees [district, appeals, supreme]

        // State
        Status  status;
        uint256 createdAt;
        uint256 lastActivityAt;

        // Review (autonomous mode)
        uint256 reviewExpiresAt;
        uint256 reviewWindow;           // 0 = supervised

        // Disputes
        uint8   disputeLevel;           // 0=district, 1=appeals, 2=supreme
        address disputeFiler;
        address disputeLoser;
        uint256 disputeFiledAt;
        uint256 disputeRespondedAt;
        uint256 ruledAt;
        Ruling  lastRuling;
        uint8   lastEvilFlags;
        uint256 cumulativeOracleFees;

        // Transcript
        bytes32 transcriptHead;             // hash of latest anchored message
        uint256 transcriptLen;              // number of messages at last anchor

        // Payout addresses (default to principal/agent, can be changed)
        address principalAccount;
        address agentAccount;
    }

    mapping(bytes32 => Contract) public contracts;
    uint256 public contractCount;

    // ══════════════════════════════════════════════════════════════
    //  EVENTS
    // ══════════════════════════════════════════════════════════════

    event Posted(bytes32 indexed id, address indexed principal, address platform, address oracle, uint256 bounty);
    event Bonded(bytes32 indexed id, address indexed agent, uint256 bond);
    event Accepted(bytes32 indexed id);
    event Declined(bytes32 indexed id, address indexed agent);
    event FixSubmitted(bytes32 indexed id, bytes32 fixHash);
    event Verified(bytes32 indexed id, bool success);
    event ReviewStarted(bytes32 indexed id, uint256 expiresAt);
    event AutoFulfilled(bytes32 indexed id);
    event DisputeFiled(bytes32 indexed id, address indexed filer, uint8 tier);
    event DisputeResponded(bytes32 indexed id, address indexed responder);
    event DisputeEscalated(bytes32 indexed id, uint8 tier);
    event Ruled(bytes32 indexed id, Ruling ruling, uint8 evilFlags, uint8 tier, uint256 tierFee);
    event Appealed(bytes32 indexed id, address indexed appellant, uint8 newTier);
    event Halted(bytes32 indexed id);
    event BackedOut(bytes32 indexed id, address indexed party, bool inGrace);
    event TimedOut(bytes32 indexed id, string reason);
    event DisputeRefused(bytes32 indexed id);
    event Settled(bytes32 indexed id, uint256 toPrincipal, uint256 toAgent, uint256 toCharity, uint256 toOracle);
    event TranscriptAnchored(bytes32 indexed id, bytes32 head, uint256 len);

    // ══════════════════════════════════════════════════════════════
    //  POST
    // ══════════════════════════════════════════════════════════════

    /// @notice Create a new fix contract.
    ///         msg.value = bounty + sum(courtFees).
    ///         Platform fee is NOT included — platform takes it off-chain before calling this.
    /// @param _principal    The actual principal (user). Payouts go to this address.
    ///                      Pass msg.sender if posting directly (no platform).
    /// @param _cancelFee    The platform fee that was already taken off-chain.
    ///                      Stored as the backout penalty — so if the other party backs out,
    ///                      you get compensated for the fee you already lost.
    function post(
        bytes32 id,
        address _principal,
        address _platform,
        address _oracle,
        address _charity,
        uint256 _minBond,
        uint256 _cancelFee,
        uint256 _reviewWindow,
        uint256[3] calldata _courtFees
    ) external payable {
        require(contracts[id].createdAt == 0, "id taken");
        require(_principal != address(0), "no principal");

        uint256 totalCourt = _courtFees[0] + _courtFees[1] + _courtFees[2];
        require(msg.value > totalCourt, "must send bounty + court fees");
        uint256 bounty = msg.value - totalCourt;

        // Agent bond must cover court fees + cancel penalty
        uint256 minFloor = totalCourt > _cancelFee ? totalCourt : _cancelFee;
        uint256 effectiveMinBond = _minBond > minFloor ? _minBond : minFloor;

        Contract storage c = contracts[id];
        c.principal        = _principal;
        c.platform         = _platform;
        c.oracle           = _oracle;
        c.charity          = _charity;
        c.bounty           = bounty;
        c.principalBond    = totalCourt;
        c.minBond          = effectiveMinBond;
        c.cancelFee        = _cancelFee;
        c.courtFees        = _courtFees;
        c.status           = Status.Open;
        c.createdAt        = block.timestamp;
        c.lastActivityAt   = block.timestamp;
        c.reviewWindow     = _reviewWindow;
        c.principalAccount = _principal;

        contractCount++;
        emit Posted(id, _principal, _platform, _oracle, bounty);
    }

    // ══════════════════════════════════════════════════════════════
    //  LIFECYCLE
    // ══════════════════════════════════════════════════════════════

    /// @notice Agent bonds to a contract. Requires platform-signed approval.
    function bond(bytes32 id, bytes calldata platformApproval) external payable {
        Contract storage c = contracts[id];
        require(c.status == Status.Open, "not open");
        require(msg.sender != c.principal, "can't bond own");
        require(msg.value >= c.minBond, "bond too low");

        if (c.platform != address(0)) {
            bytes32 hash = keccak256(abi.encodePacked(id, msg.sender, "bond"));
            bytes32 ethHash = _ethSignedHash(hash);
            require(_recoverSigner(ethHash, platformApproval) == c.platform, "not platform-approved");
        }

        c.agent          = msg.sender;
        c.agentBond      = msg.value;
        c.agentAccount   = msg.sender;
        c.status         = Status.Investigating;
        c.lastActivityAt = block.timestamp;
        emit Bonded(id, msg.sender, msg.value);
    }

    function accept(bytes32 id) external {
        Contract storage c = contracts[id];
        require(c.status == Status.Investigating, "not investigating");
        require(msg.sender == c.agent, "not agent");
        c.status         = Status.InProgress;
        c.lastActivityAt = block.timestamp;
        emit Accepted(id);
    }

    function decline(bytes32 id) external {
        Contract storage c = contracts[id];
        require(c.status == Status.Investigating, "not investigating");
        require(msg.sender == c.agent, "not agent");
        uint256 refund   = c.agentBond;
        c.agent          = address(0);
        c.agentBond      = 0;
        c.agentAccount   = address(0);
        c.status         = Status.Open;
        c.lastActivityAt = block.timestamp;
        _send(msg.sender, refund);
        emit Declined(id, msg.sender);
    }

    function submitFix(bytes32 id, bytes32 fixHash) external {
        Contract storage c = contracts[id];
        require(c.status == Status.InProgress, "not in progress");
        require(msg.sender == c.agent, "not agent");
        c.lastActivityAt = block.timestamp;
        emit FixSubmitted(id, fixHash);
        if (c.reviewWindow > 0) {
            c.status          = Status.Review;
            c.reviewExpiresAt = block.timestamp + c.reviewWindow;
            emit ReviewStarted(id, c.reviewExpiresAt);
        }
    }

    function verify(bytes32 id, bool success) external {
        Contract storage c = contracts[id];
        require(c.status == Status.InProgress || c.status == Status.Review, "not verifiable");
        require(msg.sender == c.principal, "not principal");
        c.lastActivityAt = block.timestamp;
        emit Verified(id, success);
        if (success) {
            _finalSettle(id, Ruling.Fulfilled, 0, address(0));
        } else if (c.status == Status.Review) {
            c.status = Status.InProgress;
        }
    }

    function autoFulfill(bytes32 id) external {
        Contract storage c = contracts[id];
        require(c.status == Status.Review, "not in review");
        require(block.timestamp >= c.reviewExpiresAt, "review window open");
        emit AutoFulfilled(id);
        _finalSettle(id, Ruling.Fulfilled, 0, address(0));
    }

    // ══════════════════════════════════════════════════════════════
    //  BACK OUT / TIMEOUTS
    // ══════════════════════════════════════════════════════════════

    function backOut(bytes32 id) external {
        Contract storage c = contracts[id];
        require(c.status == Status.InProgress || c.status == Status.Review, "can't back out");
        require(msg.sender == c.principal || msg.sender == c.agent, "not a party");
        bool inGrace = (block.timestamp - c.createdAt) <= GRACE_PERIOD;
        emit BackedOut(id, msg.sender, inGrace);
        if (inGrace) {
            _settleGraceBackout(id);
        } else {
            _settleBackout(id, msg.sender);
        }
    }

    /// @notice No agent picked up. Principal gets full refund.
    function cancelStale(bytes32 id) external {
        Contract storage c = contracts[id];
        require(c.status == Status.Open, "not open");
        require(block.timestamp > c.createdAt + PICKUP_TIMEOUT, "not stale");
        c.status = Status.Canceled;
        // Full refund — platform fee was already taken off-chain, nothing to deduct
        _send(c.principalAccount, c.bounty + c.principalBond);
        emit TimedOut(id, "unclaimed");
        emit Settled(id, c.bounty + c.principalBond, 0, 0, 0);
    }

    function cancelAbandoned(bytes32 id) external {
        Contract storage c = contracts[id];
        require(c.status == Status.InProgress || c.status == Status.Investigating, "not active");
        require(block.timestamp > c.lastActivityAt + ABANDONMENT_TIMEOUT, "not abandoned");
        emit TimedOut(id, "abandoned");
        _settleBackout(id, c.agent);
    }

    // ══════════════════════════════════════════════════════════════
    //  DISPUTES
    // ══════════════════════════════════════════════════════════════

    function fileDispute(bytes32 id) external {
        Contract storage c = contracts[id];
        require(c.status == Status.InProgress || c.status == Status.Review, "can't dispute");
        require(msg.sender == c.principal || msg.sender == c.agent, "not a party");
        require(c.oracle != address(0), "no oracle");
        c.status              = Status.AwaitResponse;
        c.disputeFiler        = msg.sender;
        c.disputeFiledAt      = block.timestamp;
        c.disputeRespondedAt  = 0;
        c.lastActivityAt      = block.timestamp;
        emit DisputeFiled(id, msg.sender, c.disputeLevel);
    }

    function respondDispute(bytes32 id) external {
        Contract storage c = contracts[id];
        require(c.status == Status.AwaitResponse, "no pending dispute");
        require(msg.sender != c.disputeFiler, "can't respond to own");
        require(msg.sender == c.principal || msg.sender == c.agent, "not a party");
        require(block.timestamp <= c.disputeFiledAt + RESPONSE_WINDOW, "window closed");
        c.disputeRespondedAt = block.timestamp;
        c.status             = Status.Disputed;
        c.lastActivityAt     = block.timestamp;
        emit DisputeResponded(id, msg.sender);
    }

    function escalateDispute(bytes32 id) external {
        Contract storage c = contracts[id];
        require(c.status == Status.AwaitResponse, "no pending dispute");
        require(block.timestamp > c.disputeFiledAt + RESPONSE_WINDOW, "window still open");
        c.status = Status.Disputed;
        emit DisputeEscalated(id, c.disputeLevel);
    }

    function rule(bytes32 id, Ruling ruling, uint8 evilFlags) external {
        Contract storage c = contracts[id];
        require(msg.sender == c.oracle, "not oracle");
        require(c.status == Status.Disputed || c.status == Status.Halted, "not awaiting ruling");

        uint256 deadline;
        if (c.status == Status.Halted) {
            deadline = c.disputeFiledAt + RULING_TIMEOUT;
        } else {
            deadline = c.disputeFiledAt + RESPONSE_WINDOW + RULING_TIMEOUT;
        }
        require(block.timestamp <= deadline, "too late, use voidDispute()");

        uint8 tier = c.disputeLevel;
        uint256 tierFee = c.courtFees[tier];

        address loser;
        if (ruling == Ruling.Fulfilled) {
            loser = c.disputeFiler == c.principal ? c.principal : c.agent;
        } else if (ruling == Ruling.Canceled) {
            loser = c.disputeFiler == c.agent ? c.agent : c.principal;
        } else {
            loser = c.disputeFiler;
        }

        c.cumulativeOracleFees += tierFee;
        _send(c.oracle, tierFee);

        c.disputeLoser  = loser;
        c.lastRuling    = ruling;
        c.lastEvilFlags = evilFlags;
        c.ruledAt       = block.timestamp;

        emit Ruled(id, ruling, evilFlags, tier, tierFee);

        if (tier >= 2) {
            _finalSettle(id, ruling, evilFlags, loser);
        } else {
            c.status         = Status.Ruled;
            c.lastActivityAt = block.timestamp;
        }
    }

    function appeal(bytes32 id) external {
        Contract storage c = contracts[id];
        require(c.status == Status.Ruled, "no ruling to appeal");
        require(msg.sender == c.disputeLoser, "only loser can appeal");
        require(c.disputeLevel < 2, "supreme is final");
        require(block.timestamp <= c.ruledAt + APPEAL_WINDOW, "appeal window closed");
        c.disputeLevel++;
        c.disputeFiledAt     = block.timestamp;
        c.disputeRespondedAt = 0;
        c.status             = Status.AwaitResponse;
        c.lastActivityAt     = block.timestamp;
        emit Appealed(id, msg.sender, c.disputeLevel);
    }

    function finalizeRuling(bytes32 id) external {
        Contract storage c = contracts[id];
        require(c.status == Status.Ruled, "no pending ruling");
        require(block.timestamp > c.ruledAt + APPEAL_WINDOW, "appeal window still open");
        _finalSettle(id, c.lastRuling, c.lastEvilFlags, c.disputeLoser);
    }

    function voidDispute(bytes32 id) external {
        Contract storage c = contracts[id];
        require(c.status == Status.Disputed || c.status == Status.Halted, "not in dispute");
        uint256 deadline;
        if (c.status == Status.Halted) {
            deadline = c.disputeFiledAt + RULING_TIMEOUT;
        } else {
            deadline = c.disputeFiledAt + RESPONSE_WINDOW + RULING_TIMEOUT;
        }
        require(block.timestamp > deadline, "oracle still has time");
        emit TimedOut(id, "oracle timeout");
        _settleOrFallback(id);
    }

    function refuseDispute(bytes32 id) external {
        Contract storage c = contracts[id];
        require(msg.sender == c.oracle, "not oracle");
        require(c.status == Status.Disputed || c.status == Status.Halted, "not in dispute");
        emit DisputeRefused(id);
        _settleOrFallback(id);
    }

    // ══════════════════════════════════════════════════════════════
    //  EMERGENCY HALT
    // ══════════════════════════════════════════════════════════════

    function halt(bytes32 id) external {
        Contract storage c = contracts[id];
        require(msg.sender == c.principal, "not principal");
        require(c.status == Status.InProgress || c.status == Status.Review, "can't halt");
        require(c.oracle != address(0), "no oracle");
        c.status         = Status.Halted;
        c.disputeFiler   = msg.sender;
        c.disputeFiledAt = block.timestamp;
        c.lastActivityAt = block.timestamp;
        emit Halted(id);
    }

    // ══════════════════════════════════════════════════════════════
    //  TRANSCRIPT + ACCOUNTS
    // ══════════════════════════════════════════════════════════════

    /// @notice Anchor transcript head hash on-chain.
    ///         The transcript is an Ed25519-signed hash chain. Each message links
    ///         to the previous via prev_hash. Anchoring the head pins the whole chain.
    ///         Can be called multiple times (platform anchors periodically).
    /// @param head  Hash of the latest transcript message
    /// @param len   Total number of messages in the transcript at this point
    function anchorTranscript(bytes32 id, bytes32 head, uint256 len) external {
        Contract storage c = contracts[id];
        require(
            msg.sender == c.principal || msg.sender == c.agent || msg.sender == c.platform,
            "not authorized"
        );
        _requireActive(c);
        require(len >= c.transcriptLen, "can't shrink transcript");
        c.transcriptHead = head;
        c.transcriptLen  = len;
        emit TranscriptAnchored(id, head, len);
    }

    function setPrincipalAccount(bytes32 id, address account) external {
        Contract storage c = contracts[id];
        require(msg.sender == c.principal, "not principal");
        _requireActive(c);
        c.principalAccount = account;
    }

    function setAgentAccount(bytes32 id, address account) external {
        Contract storage c = contracts[id];
        require(msg.sender == c.agent, "not agent");
        _requireActive(c);
        c.agentAccount = account;
    }

    // ══════════════════════════════════════════════════════════════
    //  SETTLEMENT (internal)
    // ══════════════════════════════════════════════════════════════

    /// @dev Final settlement. No platform fee — platform already took it.
    ///      Routes bounty + remaining bonds. Oracle fees already paid per-tier.
    function _finalSettle(
        bytes32 id,
        Ruling ruling,
        uint8 evilFlags,
        address loser
    ) internal {
        Contract storage c = contracts[id];

        uint256 bounty     = c.bounty;
        uint256 pBond      = c.principalBond;
        uint256 aBond      = c.agentBond;
        uint256 oraclePaid = c.cumulativeOracleFees;

        bool evilAgent     = (evilFlags & EVIL_AGENT) != 0;
        bool evilPrincipal = (evilFlags & EVIL_PRINCIPAL) != 0;

        uint256 toPrincipal;
        uint256 toAgent;
        uint256 toCharity;

        // ── Route bounty ──────────────────────────────────────────
        if (ruling == Ruling.Fulfilled) {
            if (evilPrincipal) toCharity += bounty;
            else               toAgent += bounty;
        } else if (ruling == Ruling.Canceled) {
            if (evilAgent && evilPrincipal) toCharity += bounty;
            else if (evilPrincipal)         toCharity += bounty;
            else                             toPrincipal += bounty;
        } else {
            // Impossible — bounty returned to principal
            toPrincipal += bounty;
        }

        // ── Route bonds (oracle fees already deducted from loser) ─
        if (loser != address(0)) {
            uint256 loserBond  = loser == c.agent ? aBond : pBond;
            uint256 winnerBond = loser == c.agent ? pBond : aBond;
            bool loserEvil     = loser == c.agent ? evilAgent : evilPrincipal;
            bool winnerEvil    = loser == c.agent ? evilPrincipal : evilAgent;

            uint256 loserRemainder = loserBond > oraclePaid ? loserBond - oraclePaid : 0;

            if (loserEvil && loserRemainder > 0) {
                toCharity += loserRemainder;
            } else if (loser == c.agent) {
                toAgent += loserRemainder;
            } else {
                toPrincipal += loserRemainder;
            }

            if (winnerEvil) {
                toCharity += winnerBond;
            } else if (loser == c.agent) {
                toPrincipal += winnerBond;
            } else if (winnerBond > 0) {
                toAgent += winnerBond;
            }
        } else {
            // No dispute — both bonds returned in full
            toPrincipal += pBond;
            if (aBond > 0) toAgent += aBond;
        }

        c.status = ruling == Ruling.Fulfilled ? Status.Fulfilled : Status.Canceled;

        if (toPrincipal > 0) _send(c.principalAccount, toPrincipal);
        if (toAgent > 0)     _send(c.agentAccount, toAgent);
        if (toCharity > 0)   _send(c.charity, toCharity);

        emit Settled(id, toPrincipal, toAgent, toCharity, oraclePaid);
    }

    /// @dev Backout settlement (post-grace). Backer pays cancelFee as penalty.
    ///      cancelFee = platform fee already taken, so the other party breaks even.
    function _settleBackout(bytes32 id, address backer) internal {
        Contract storage c = contracts[id];

        uint256 bounty = c.bounty;
        uint256 pBond  = c.principalBond;
        uint256 aBond  = c.agentBond;
        uint256 fee    = c.cancelFee;

        uint256 toPrincipal;
        uint256 toAgent;

        if (backer == c.agent) {
            // Agent backs out → penalty from agent bond compensates principal
            uint256 penalty = fee > aBond ? aBond : fee;
            toPrincipal = bounty + pBond + penalty;
            toAgent     = aBond - penalty;
        } else {
            // Principal backs out → penalty from bounty compensates agent
            uint256 penalty = fee > bounty ? bounty : fee;
            toPrincipal = (bounty - penalty) + pBond;
            toAgent     = penalty + aBond;
        }

        c.status = Status.Canceled;
        if (toPrincipal > 0) _send(c.principalAccount, toPrincipal);
        if (toAgent > 0)     _send(c.agentAccount, toAgent);

        emit Settled(id, toPrincipal, toAgent, 0, 0);
    }

    /// @dev Grace period backout. Everything returned.
    function _settleGraceBackout(bytes32 id) internal {
        Contract storage c = contracts[id];
        c.status = Status.Canceled;

        uint256 toPrincipal = c.bounty + c.principalBond;
        uint256 toAgent     = c.agentBond;

        if (toPrincipal > 0) _send(c.principalAccount, toPrincipal);
        if (toAgent > 0)     _send(c.agentAccount, toAgent);

        emit Settled(id, toPrincipal, toAgent, 0, 0);
    }

    /// @dev Void settlement (oracle no-show). Everything returned minus already-paid fees.
    function _settleVoid(bytes32 id) internal {
        Contract storage c = contracts[id];
        c.status = Status.Voided;

        uint256 oraclePaid  = c.cumulativeOracleFees;
        uint256 toPrincipal = c.bounty + c.principalBond;
        uint256 toAgent     = c.agentBond;

        // Deduct already-paid oracle fees from filer's return
        if (oraclePaid > 0) {
            if (c.disputeFiler == c.principal && toPrincipal >= oraclePaid) {
                toPrincipal -= oraclePaid;
            } else if (c.disputeFiler == c.agent && toAgent >= oraclePaid) {
                toAgent -= oraclePaid;
            }
        }

        if (toPrincipal > 0) _send(c.principalAccount, toPrincipal);
        if (toAgent > 0)     _send(c.agentAccount, toAgent);

        emit Settled(id, toPrincipal, toAgent, 0, oraclePaid);
    }

    /// @dev If a prior tier ruled, finalize that ruling. Otherwise void.
    function _settleOrFallback(bytes32 id) internal {
        Contract storage c = contracts[id];
        if (c.disputeLevel > 0 && c.ruledAt > 0) {
            _finalSettle(id, c.lastRuling, c.lastEvilFlags, c.disputeLoser);
        } else {
            _settleVoid(id);
        }
    }

    // ══════════════════════════════════════════════════════════════
    //  HELPERS
    // ══════════════════════════════════════════════════════════════

    function _send(address to, uint256 amount) internal {
        if (to == address(0) || amount == 0) return;
        (bool ok, ) = payable(to).call{value: amount}("");
        require(ok, "transfer failed");
    }

    function _requireActive(Contract storage c) internal view {
        require(
            c.status != Status.Fulfilled &&
            c.status != Status.Canceled &&
            c.status != Status.Voided,
            "resolved"
        );
    }

    function _recoverSigner(bytes32 hash, bytes memory sig) internal pure returns (address) {
        require(sig.length == 65, "bad sig length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        if (v < 27) v += 27;
        return ecrecover(hash, v, r, s);
    }

    function _ethSignedHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    // ══════════════════════════════════════════════════════════════
    //  VIEWS
    // ══════════════════════════════════════════════════════════════

    function getStatus(bytes32 id) external view returns (Status) {
        return contracts[id].status;
    }

    function getParties(bytes32 id) external view returns (
        address principal, address agent,
        address platform_, address oracle_, address charity_
    ) {
        Contract storage c = contracts[id];
        return (c.principal, c.agent, c.platform, c.oracle, c.charity);
    }

    function getMoney(bytes32 id) external view returns (
        uint256 bounty, uint256 principalBond, uint256 agentBond,
        uint256 minBond, uint256 cancelFee, uint256 oracleFeesPaid
    ) {
        Contract storage c = contracts[id];
        return (c.bounty, c.principalBond, c.agentBond, c.minBond, c.cancelFee, c.cumulativeOracleFees);
    }

    function getCourtFees(bytes32 id) external view returns (uint256[3] memory) {
        return contracts[id].courtFees;
    }

    function getTotalCourtFees(bytes32 id) external view returns (uint256) {
        Contract storage c = contracts[id];
        return c.courtFees[0] + c.courtFees[1] + c.courtFees[2];
    }

    function getCumulativeFeeThrough(bytes32 id, uint8 tier) external view returns (uint256) {
        Contract storage c = contracts[id];
        uint256 total;
        for (uint8 i = 0; i <= tier && i < 3; i++) total += c.courtFees[i];
        return total;
    }

    function getDispute(bytes32 id) external view returns (
        uint8 level, address filer, address loser,
        uint256 filedAt, uint256 respondedAt, uint256 _ruledAt
    ) {
        Contract storage c = contracts[id];
        return (c.disputeLevel, c.disputeFiler, c.disputeLoser,
                c.disputeFiledAt, c.disputeRespondedAt, c.ruledAt);
    }

    function getTiming(bytes32 id) external view returns (
        uint256 createdAt, uint256 lastActivityAt,
        uint256 reviewExpiresAt, uint256 reviewWindow
    ) {
        Contract storage c = contracts[id];
        return (c.createdAt, c.lastActivityAt, c.reviewExpiresAt, c.reviewWindow);
    }

    function getTranscriptLen(bytes32 id) external view returns (uint256) {
        return contracts[id].transcriptLen;
    }
}
