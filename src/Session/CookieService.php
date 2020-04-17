<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Session;

use Codeacious\Security\Exception\ConfigurationException;
use Codeacious\Security\Session\TokenProvider\TokenProviderInterface;
use Codeacious\Security\User;

/**
 * Provides functionality for setting or clearing the current web session user. The session user is
 * persisted across requests using a cookie.
 */
class CookieService extends PersistenceMethod
{
    /**
     * @var array
     */
    private $config;

    /**
     * @var TokenProviderInterface
     */
    private $tokenProvider;

    /**
     * @var string
     */
    private $cookieValue;


    /**
     * @param array $config
     * @throws ConfigurationException
     */
    public function __construct(array $config)
    {
        $this->config = $config;
        $requiredKeys = array('name', 'validity_period', 'is_secure');
        foreach ($requiredKeys as $key)
        {
            if (!isset($this->config[$key]))
                throw new ConfigurationException('Missing configuration key '.$key);
        }
    }

    /**
     * @return TokenProviderInterface
     */
    public function getTokenProvider()
    {
        return $this->tokenProvider;
    }

    /**
     * @param mixed $tokenProvider
     * @return $this
     */
    public function setTokenProvider($tokenProvider)
    {
        $this->tokenProvider = $tokenProvider;
        return $this;
    }

    /**
     * @param string $value
     * @return $this
     */
    public function setCookieValue($value)
    {
        $validityPeriod = $this->_getConfig('validity_period');
        $expires = 0;
        if ($validityPeriod > 0)
            $expires = time() + $validityPeriod;

        setcookie(
            $this->_getConfig('name'),
            $value,
            $expires,
            '/',
            $this->_getConfig('domain', ''),
            $this->_getConfig('is_secure', false),
            $this->_getConfig('http_only', false)
        );
        $this->cookieValue = $value;
        return $this;
    }

    /**
     * @return string
     */
    public function getCookieValue()
    {
        if (empty($this->cookieValue))
        {
            $cookieName = $this->_getConfig('name');
            if (empty($_COOKIE[$cookieName]))
                $this->cookieValue = null;
            else
                $this->cookieValue = $_COOKIE[$cookieName];
        }
        return $this->cookieValue;
    }

    /**
     * @return void
     */
    public function destroyCookie()
    {
        $cookieName = $this->_getConfig('name');
        if (isset($_COOKIE[$cookieName]))
            unset($_COOKIE[$cookieName]);

        setcookie(
            $cookieName,
            '',
            time() - 3600,
            '/',
            $this->_getConfig('domain', ''),
            $this->_getConfig('is_secure', false),
            $this->_getConfig('http_only', false)
        );

        $this->cookieValue = null;
    }

    /**
     * @param User $user
     * @param User|null $realUser
     * @return void
     */
    protected function persistState(User $user, User $realUser = null)
    {
        $token = $this->tokenProvider->generateToken($user, $realUser);
        $this->setCookieValue($token);
    }

    /**
     * @return void
     */
    protected function clearState()
    {
        if (($cookieValue = $this->getCookieValue()))
            $this->tokenProvider->invalidateToken($cookieValue);
        $this->destroyCookie();
    }

    /**
     * @param string $name
     * @param mixed $default
     * @return mixed
     */
    protected function _getConfig($name, $default=null)
    {
        if (!isset($this->config[$name]))
            return $default;

        return $this->config[$name];
    }
}