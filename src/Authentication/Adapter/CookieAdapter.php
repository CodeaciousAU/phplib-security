<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication\Adapter;

use Codeacious\Security\Session\CookieService;
use Laminas\Authentication\Adapter\AdapterInterface;
use Laminas\Authentication\Adapter\Exception\ExceptionInterface;
use Laminas\Authentication\Result;

/**
 * This adapter authenticates session cookies created by the CookieService.
 */
class CookieAdapter implements AdapterInterface
{
    /**
     * @var CookieService
     */
    private $cookieService;


    /**
     * @param CookieService $cookieService
     * @return $this
     */
    public function setCookieService($cookieService)
    {
        $this->cookieService = $cookieService;
        return $this;
    }

    /**
     * Performs an authentication attempt
     *
     * @return Result
     * @throws ExceptionInterface If authentication cannot be performed
     */
    public function authenticate()
    {
        $token = $this->cookieService->getCookieValue();
        if (empty($token))
        {
            return new Result(Result::FAILURE_IDENTITY_AMBIGUOUS, null,
                ['No authentication cookie was present']);
        }

        return $this->cookieService->getTokenProvider()->authenticateToken($token);
    }
}