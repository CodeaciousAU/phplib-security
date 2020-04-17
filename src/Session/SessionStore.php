<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Session;

use Codeacious\Security\Authentication\Assertion;
use Codeacious\Security\User;
use Laminas\Session\Container;

/**
 * Provides functionality for setting or clearing the current web session user. The session user is
 * persisted across requests by storing it in a Laminas\Session container.
 */
class SessionStore extends AssertionStore
{
    /**
     * @var Container
     */
    private $container;


    /**
     * @param Container $container
     */
    public function __construct(Container $container)
    {
        $this->container = $container;
    }

    /**
     * Set the logged-in user for the current session.
     *
     * @param User|null $user Pass null to clear the session user
     * @param User|null $realUser If not null, this starts a session whereby $realUser is
     *    impersonating $user. Not applicable if $user is null.
     * @return void
     */
    public function setSessionUser(User $user = null, User $realUser = null)
    {
        parent::setSessionUser($user, $realUser);

        //Generate a new session ID, in accordance with good security practice
        $this->container->getManager()->regenerateId();
    }

    /**
     * @return Assertion|null
     */
    public function getAssertion()
    {
        if (!is_array($this->container['assertion']))
            return null;

        return new Assertion($this->container['assertion']);
    }

    /**
     * @param Assertion|null $assertion
     * @return void
     */
    protected function persistAssertion(Assertion $assertion = null)
    {
        $this->container['assertion'] = $assertion ? $assertion->getArrayCopy() : null;
    }
}