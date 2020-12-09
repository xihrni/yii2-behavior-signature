<?php

namespace xihrni\yii2\behaviors;

use Yii;
use yii\web\ForbiddenHttpException;
use yii\base\InvalidConfigException;
use yii\helpers\ArrayHelper;

/**
 * 鉴权行为
 *
 * Class SignatureBehavior
 * @package xihrni\yii2\behaviors
 */
class SignatureBehavior extends \yii\base\ActionFilter
{
    /**
     * @var bool [$switchOn = true] 开关
     */
    public $switchOn = true;

    /**
     * @var array [$optional = []] 过滤操作
     */
    public $optional = [];

    /**
     * @var bool [$isHint = false] 是否提示具体错误
     */
    public $isHint = false;

    /**
     * @var array $clientSecrets 客户端秘钥集合
     */
    public $clientSecrets;


    /**
     * @inheritdoc
     * @throws InvalidConfigException
     */
    public function init()
    {
        parent::init();

        if ($this->clientSecrets === null) {
            throw new InvalidConfigException(Yii::t('app/error', '{param} must be set.', ['param' => 'config']));
        }
    }

    /**
     * @inheritdoc
     * @throws HttpException
     */
    public function beforeAction($action)
    {
        $isPassed = parent::beforeAction($action);
        // 验证父类方法
        if (!$isPassed) {
            return $isPassed;
        }

        // 判断开关
        if (!$this->switchOn) {
            return true;
        }

        // 过滤操作
        if (in_array($action->id, $this->optional)) {
            return true;
        }

        /**
         * $data['_c']; // 客户端ID
         * $data['_d']; // 时间戳（秒）
         * $data['_s']; // 计算数值（进一取整（时间戳取后6位 * 12345.6789））
         * $data['_t']; // Token（SHA1（MD5（URL（不带_t参数）） + 客户端ID + 时间戳 + 计算数值 + 客户端秘钥）
         */
        $data    = Yii::$app->request->get();
        $fullUrl = Yii::$app->request->absoluteUrl; // 完整URL

        // 判断参数是否存在
        if (!isset($data['_c']) || !isset($data['_d']) || !isset($data['_s']) || !isset($data['_t'])) {
            throw new ForbiddenHttpException($this->isHint ? '参数' : 403);
        }

        // 判断时间不可大于60秒
        if (time() - $data['_d'] > 60) {
            throw new ForbiddenHttpException($this->isHint ? '时间' : 403);
        }

        // 判断计算数值
        if (ceil(substr($data['_d'], -6) * 12345.6789) != $data['_s']) {
            throw new ForbiddenHttpException($this->isHint ? '计算数值' : 403);
        }

        // 判断客户端ID
        $clientSecrets = ArrayHelper::index($this->clientSecrets, 'id');
        $clientSecret  = $clientSecrets[$data['_c']];

        if (!$clientSecret) {
            throw new ForbiddenHttpException($this->isHint ? '客户端ID' : 403);
        }

        // 判断Token
        $url   = md5(str_replace('&_t=' . $data['_t'], '', $fullUrl));
        $token = sha1($url . $data['_c'] . $data['_d'] . $data['_s'] . $clientSecret['secret']);
        if ($token != $data['_t']) {
            throw new ForbiddenHttpException($this->isHint ? 'Token' : 403);
        }

        return true;
    }
}
