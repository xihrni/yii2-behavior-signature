# Yii2 鉴权行为
基于 Yii2 的接口鉴权行为

## Install
```composer
$ composer require xihrni/yii2-behavior-signature
```

## Usage
### 生成签名步骤
1. 从服务端拿到客户端ID和秘钥
2. 准备好 `_c`、`_d`、`_s`、`_t` 四个参数
    1. _c：客户端ID
    2. _d：当前时间戳（秒）
    3. _s：计算数值，取当前时间戳（秒）后6位 * 12345.6789，再进行进一取整
    4. _t：Token，将上面三个参数拼接到 URL 参数最后进行 MD5 加密后再拼接上面三个参数的值，接着拼接客户端秘钥，最后进行 SHA1 加密
3. 将上面四个参数拼接到需要访问的 URL 参数最后进行请求

## Demo
### 客户端签名生成
```php
<?php

$c = '1001'; // 客户端ID
$d = time(); // 时间戳（秒）
$s = ceil(substr($d, -6) * 12345.6789); // 计算数值

$url = 'http://xxx.com/index/index?page=1&per-page=10';
$url = explode('?', $url);
$params = trim($url[1] . '&_c=' . $c . '&_d=' . $d . '&_s=' . $s, '&');
$newUrl = $url[0] . '?' . $params;

$t = sha1(md5($newUrl) . $c . $d . $s . 'b8c37e33defde51cf91e1e03e51657da'); // Token

$newUrl .= '&_t=' . $t;
file_put_contents($newUrl);
```

### 服务端验证调用
```php
<?php

namespace app\controllers;

use xihrni\yii2\behaviors\SignatureBehavior;

class IndexController extends \yii\web\Controller
{
    public function behaviors()
    {
        return array_merge(parent::behaviors(), [
            'signature' => [
                'class' => SignatureBehavior::className(),
                'switchOn' => true,
                'optional' => ['view'],
                'clientSecrets' => [
                    ['id' => 1001, 'secret' => 'b8c37e33defde51cf91e1e03e51657da'],
                    ['id' => 1002, 'secret' => 'fba9d88164f3e2d9109ee770223212a0'],
                    // ...
                ],
            ],
        ]);
    }

    public function actionIndex()
    {}

    public function actionView($id)
    {}
}
```