<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication\Adapter;

use Codeacious\Security\Session\AssertionStore;
use Laminas\Authentication\Adapter\AdapterInterface;
use Laminas\Authentication\Adapter\Exception\ExceptionInterface;
use Laminas\Authentication\Result;

class AssertionStoreAdapter implements AdapterInterface
{
    /**
     * @var AssertionStore
     */
    private $store;


    public function __construct(AssertionStore $store)
    {
        $this->store = $store;
    }

    /**
     * Performs an authentication attempt
     *
     * @return Result
     * @throws ExceptionInterface If authentication cannot be performed
     */
    public function authenticate()
    {
        $assertion = $this->store->getAssertion();
        if ($assertion === null)
        {
            return new Result(Result::FAILURE_IDENTITY_AMBIGUOUS, null,
                ['No user identity was present in the store']);
        }
        return new Result(Result::SUCCESS, $assertion);
    }
}