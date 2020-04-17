<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication;

use Codeacious\Security\User;

interface UserLookupStrategy
{
    /**
     * @param Assertion $assertion
     * @return User|null
     */
    public function getAssertedUser(Assertion $assertion);

    /**
     * @param Assertion $assertion
     * @return User|null
     */
    public function getRealUser(Assertion $assertion);
}