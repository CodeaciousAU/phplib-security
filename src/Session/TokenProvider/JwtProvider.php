<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Session\TokenProvider;

use Codeacious\Security\User;
use Codeacious\Security\WebTokenManager;
use Laminas\Authentication\Result as AuthenticationResult;

/**
 * Default strategy for creating session cookie tokens. Generates a signed JWT containing the
 * user ID of the logged-in user. The benefit of using a JWT is that no session state needs to be
 * kept on the server side.
 *
 * This provider is useful as long as all the user information necessary to enforce permissions
 * can be looked up based on user ID.
 */
class JwtProvider implements TokenProviderInterface
{
    /**
     * @var WebTokenManager
     */
    protected $tokenManager;

    /**
     * @var string
     */
    protected $tokenAudience;


    /**
     * @param WebTokenManager $tokenManager
     * @return $this
     */
    public function setTokenManager($tokenManager)
    {
        $this->tokenManager = $tokenManager;
        return $this;
    }

    /**
     * @param string $tokenAudience
     * @return $this
     */
    public function setTokenAudience($tokenAudience)
    {
        $this->tokenAudience = $tokenAudience;
        return $this;
    }

    /**
     * @param User $user
     * @param User|null $realUser
     * @return string
     */
    public function generateToken(User $user, User $realUser=null)
    {
        return $this->tokenManager->createBearerToken(
            $this->tokenAudience,
            $user->getId(),
            self::TOKEN_SCOPE_WEB_ACCESS,
            $realUser ? $realUser->getId() : null
        );
    }

    /**
     * @param string $token
     * @return AuthenticationResult
     */
    public function authenticateToken($token)
    {
        if (!($tokenAssertion = $this->tokenManager->authenticateBearerToken($token)))
        {
            return new AuthenticationResult(AuthenticationResult::FAILURE_CREDENTIAL_INVALID, null,
                ['Cookie token is expired or invalid']);
        }

        if (!$tokenAssertion->hasScope(self::TOKEN_SCOPE_WEB_ACCESS))
        {
            return new AuthenticationResult(AuthenticationResult::FAILURE_CREDENTIAL_INVALID, null,
                ['Cookie token is not acceptable for this purpose']);
        }

        if (!empty($this->tokenAudience) && !$tokenAssertion->hasAudience($this->tokenAudience))
        {
            return new AuthenticationResult(AuthenticationResult::FAILURE_CREDENTIAL_INVALID, null,
                ['Cookie token is not acceptable for this web domain']);
        }

        return new AuthenticationResult(AuthenticationResult::SUCCESS, $tokenAssertion);
    }

    /**
     * @param string $token
     * @return void
     */
    public function invalidateToken($token)
    {
        //JWTs cannot be revoked because they are stateless
    }


    /**
     * The scope value used in the session JWT.
     */
    const TOKEN_SCOPE_WEB_ACCESS = 'web_ui';
}