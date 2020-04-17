<?php
/**
 * @author Glenn Schmidt <glenn@codeacious.com>
 */

namespace Codeacious\Security\Authentication\Adapter;

use Codeacious\Security\Authentication\JwtAssertion;
use Laminas\Authentication\Result;
use Laminas\Http\Request;
use Lcobucci\JWT\Claim;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\ValidationData;

/**
 * Adapter which extracts a JWT bearer token from the HTTP authorization header and verifies its
 * signature, issuer and expiration date.
 */
class JwtBearerAdapter extends BearerAdapter
{
    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var Signer\Key
     */
    private $verificationKey;

    /**
     * @var string
     */
    private $issuer;


    public function __construct(Request $request, Signer $signer, Signer\Key $verificationKey,
                                string $issuer=null)
    {
        parent::__construct($request);
        $this->signer = $signer;
        $this->verificationKey = $verificationKey;
        $this->issuer = $issuer;
    }

    /**
     * @return Result
     */
    public function authenticate()
    {
        //Extract the token from the request
        $result = parent::authenticate();
        if (!$result->isValid())
            return $result;

        //Parse the token
        try
        {
            $jwt = (new Parser())->parse($result->getIdentity());
        }
        catch (\Exception $e)
        {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, null,
                ['Invalid access token']);
        }

        //Check signature
        if (!$jwt->verify($this->signer, $this->verificationKey))
        {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, null,
                ['Invalid access token']);
        }

        //Check exp, iat, nbf (if present)
        if (!$jwt->validate(new ValidationData()))
        {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, null,
                ['Access token has expired']);
        }

        //Check for mandatory claims
        $claims = array_map(fn (Claim $claim) => $claim->getValue(), $jwt->getClaims());
        if (empty($claims['exp']) || empty($claims['sub']) || empty($claims['token_type'])
            || $claims['token_type'] != 'bearer')
        {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, null,
                ['JWT is missing mandatory claims']);
        }

        //Check issuer
        if (!empty($this->issuer)
            && (empty($claims['issuer']) || $claims['issuer'] !== $this->issuer))
        {
            return new Result(Result::FAILURE_CREDENTIAL_INVALID, null,
                ['JWT has unknown issuer']);
        }

        return new Result(Result::SUCCESS, new JwtAssertion($claims));
    }
}