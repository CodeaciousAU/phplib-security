<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Session\TokenProvider;

use Codeacious\Security\User;
use Laminas\Authentication\Result as AuthenticationResult;

/**
 * Interface for objects that can generate and authenticate session cookie tokens.
 */
interface TokenProviderInterface
{
    /**
     * Generate a token that will identify the specified user when passed to authenticateToken().
     *
     * @param User $user
     * @param User|null $realUser If user impersonation is active, $realUser specifies who is doing
     *    the impersonation.
     * @return string
     */
    public function generateToken(User $user, User $realUser=null);

    /**
     * Verify the provided token and determine which user it identifies.
     *
     * @param string $token
     * @return AuthenticationResult If the result type is SUCCESS, the result identity must be an
     *    \Codeacious\Security\Authentication\Assertion
     */
    public function authenticateToken($token);

    /**
     * Invalidate the provided token, if possible, so that it cannot be authenticated in future.
     *
     * @param string $token
     * @return void
     */
    public function invalidateToken($token);
}