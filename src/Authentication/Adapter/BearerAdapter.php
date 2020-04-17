<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication\Adapter;

use Laminas\Authentication\Adapter\AbstractAdapter;
use Laminas\Authentication\Result;
use Laminas\Http\Header\Authorization;
use Laminas\Http\Request;

/**
 * Adapter which extracts a bearer token from the HTTP authorization header and stores it in
 * the authentication result.
 *
 * It only validates that the token exists, no other checks are performed.
 */
class BearerAdapter extends AbstractAdapter
{
    /**
     * @var Request
     */
    private $request;


    public function __construct(Request $request)
    {
        $this->request = $request;
    }

    /**
     * @return Result
     */
    public function authenticate()
    {
        //Find the authorization header
        $authHeader = $this->request->getHeaders()->get('Authorization');
        if (!$authHeader instanceof Authorization)
        {
            return new Result(Result::FAILURE_IDENTITY_AMBIGUOUS, null,
                ['No authorization header was present']);
        }

        //Extract the bearer token
        list($type, $token) = explode(' ', $authHeader->getFieldValue(), 2);
        if ($type !== 'Bearer' || empty($token))
        {
            return new Result(Result::FAILURE_IDENTITY_AMBIGUOUS, null,
                ['No bearer token found in authorization header']);
        }

        return new Result(Result::SUCCESS, $token);
    }
}