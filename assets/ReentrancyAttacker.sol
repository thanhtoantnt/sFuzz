contract ReentrancyAttacker {
    uint counter = 0;
    function() payable {
        counter ++;
        if (counter <= 2) {
            msg.sender.call(bytes4(255));
        }
        revert();
    }
}
