<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Session;

use Codeacious\Security\Authentication\Assertion;

class DummyStore extends AssertionStore
{
    /**
     * @return Assertion|null
     */
    public function getAssertion()
    {
        return null;
    }

    /**
     * @param Assertion|null $assertion
     * @return void
     */
    protected function persistAssertion(Assertion $assertion = null)
    {
    }
}