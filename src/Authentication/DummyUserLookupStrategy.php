<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication;

use Codeacious\Security\User;

class DummyUserLookupStrategy implements UserLookupStrategy
{
    /**
     * @param Assertion $assertion
     * @return User|null
     */
    public function getAssertedUser(Assertion $assertion)
    {
        return null;
    }

    /**
     * @param Assertion $assertion
     * @return User|null
     */
    public function getRealUser(Assertion $assertion)
    {
        return null;
    }
}