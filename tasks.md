1. Add tests for view functions (verifyProof, verifyProofs, getScore)
2. Add reentrancy test with a malicious scorer contract
3. Add fuzz tests for timestamp boundaries
4. Add tests for new validation errors (BID::invalid admin address, BID::invalid scorer address)
5. Validate commitment != 0 in registerCredential
6. Fix DefaultScorer._scoredGroupIds duplicate push bug  