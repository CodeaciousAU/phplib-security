<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Session;

use Codeacious\Security\Authentication\Assertion;
use Codeacious\Security\User;

abstract class AssertionStore extends PersistenceMethod
{
    /**
     * @return Assertion|null
     */
    public abstract function getAssertion();

    /**
     * @param Assertion|null $assertion
     * @return void
     */
    protected abstract function persistAssertion(Assertion $assertion=null);

    /**
     * @param User $user
     * @param User|null $realUser
     * @return Assertion
     */
    protected function createAssertion(User $user, User $realUser=null)
    {
        $assertion = new Assertion();
        $assertion->setUserId($user->getId())
            ->setRealUserId($realUser ? $realUser->getId() : null);
        return $assertion;
    }

    /**
     * @param User $user
     * @param User|null $realUser
     * @return void
     */
    protected function persistState(User $user, User $realUser = null)
    {
        $this->persistAssertion($this->createAssertion($user, $realUser));
    }

    /**
     * @return void
     */
    protected function clearState()
    {
        $this->persistAssertion(null);
    }
}